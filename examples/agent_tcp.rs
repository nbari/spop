use anyhow::Result;
use futures::{SinkExt, StreamExt};
use spop::{
    MAX_FRAME_SIZE_LIMIT, SpopCodec, SpopFrame, StatusCode,
    actions::VarScope,
    frame::{FramePayload, FrameType},
    frames::{Ack, AgentDisconnect, AgentHello, FrameCapabilities, HaproxyHello},
};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:12345").await?;
    println!("SPOE Agent listening on port 12345...");

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("New connection from {addr}");
        tokio::spawn(handle_connection(stream));
    }
}

/// Sends an AGENT-DISCONNECT carrying `status` and closes the connection.
///
/// The spec requires an agent that hits an error to report it this way rather than just
/// dropping the socket, so `HAProxy` can log the reason instead of guessing.
async fn disconnect(socket: &mut Framed<TcpStream, SpopCodec>, status: StatusCode) -> Result<()> {
    let frame = AgentDisconnect {
        status_code: status.to_u32(),
        message: status.message().to_string(),
    };

    eprintln!("Disconnecting: {status}");
    socket.send(Box::new(frame)).await?;
    socket.close().await?;

    Ok(())
}

async fn handle_connection(u_stream: TcpStream) -> Result<()> {
    let mut socket = Framed::new(u_stream, SpopCodec::default());

    while let Some(result) = socket.next().await {
        let frame = match result {
            Ok(f) => f,
            // HAProxy closes the connection abruptly at the end of an `option spop-check`
            // health check, and again whenever it retires an idle connection, so a reset or a
            // truncated read is a normal end of life rather than a fault. Logging those at error
            // level buries the failures that do matter.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                println!("Peer closed the connection ({})", e.kind());
                break;
            }
            Err(e) => {
                eprintln!("Frame read error: {e:?}");
                break;
            }
        };

        match frame.frame_type() {
            // Respond with AgentHello frame
            FrameType::HaproxyHello => {
                let hello = HaproxyHello::try_from(frame.payload())
                    .map_err(|_| anyhow::anyhow!("Failed to parse HaproxyHello"))?;

                let is_healthcheck = hello.healthcheck.unwrap_or(false);

                // * "version"    <STRING>
                // This is the SPOP version the agent supports. It must follow the format
                // "Major.Minor" and it must be lower or equal than one of major versions
                // announced by HAProxy. Replying with an unannounced version earns a
                // HAPROXY-DISCONNECT, so negotiate instead of assuming.
                let Some(version) = hello.negotiate_version() else {
                    return disconnect(&mut socket, StatusCode::BadVersion).await;
                };

                // Announce the smaller of what HAProxy offered and what we accept.
                let max_frame_size = match hello.negotiate_max_frame_size(MAX_FRAME_SIZE_LIMIT) {
                    Ok(size) => size,
                    Err(status) => return disconnect(&mut socket, status).await,
                };

                // Hold the peer to what was agreed: until now the codec only had the
                // conservative MAX_FRAME_SIZE_LIMIT backstop to work with.
                socket.codec_mut().set_max_frame_size(max_frame_size);

                // Create the AgentHello with the values
                let agent_hello = AgentHello {
                    version,
                    max_frame_size,
                    capabilities: vec![FrameCapabilities::Pipelining],
                };

                println!("Sending AgentHello: {:#?}", agent_hello.payload());

                match socket.send(Box::new(agent_hello)).await {
                    Ok(()) => println!("Frame sent successfully"),
                    Err(e) => eprintln!("Failed to send frame: {e:?}"),
                }

                // If "healthcheck" item was set to TRUE in the HAPROXY-HELLO frame, the
                // agent can safely close the connection without DISCONNECT frame. In all
                // cases, HAProxy will close the connection at the end of the health check.
                if is_healthcheck {
                    println!("Handled healthcheck. Closing socket.");
                    return Ok(());
                }
            }

            // Respond with AgentDisconnect frame
            FrameType::HaproxyDisconnect => {
                return disconnect(&mut socket, StatusCode::None).await;
            }

            // Respond with Ack frame
            FrameType::Notify => {
                if let FramePayload::ListOfMessages(messages) = &frame.payload() {
                    // Create the Ack frame
                    let mut ack = Ack::new(frame.metadata().stream_id, frame.metadata().frame_id);

                    for message in *messages {
                        match message.name.as_str() {
                            "check-client-ip" => {
                                let random_value: u32 = rand::random_range(0..100);
                                ack = ack.set_var(VarScope::Session, "ip_score", random_value);
                            }

                            "log-request" => {
                                ack = ack.set_var(VarScope::Transaction, "my_var", "tequila");
                            }

                            _ => {
                                eprintln!("Unsupported message: {:?}", message.name);
                            }
                        }
                    }

                    // Create the response frame
                    println!("Sending Ack: {:#?}", ack.payload());
                    socket.send(Box::new(ack)).await?;
                }
            }

            _ => {
                eprintln!("Unsupported frame type: {:?}", frame.frame_type());
            }
        }
    }

    println!("Socket closed by peer");

    Ok(())
}
