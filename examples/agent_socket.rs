use anyhow::Result;
use futures::{SinkExt, StreamExt};
use spop::{
    SpopCodec, SpopFrame, Version,
    actions::VarScope,
    frame::{FramePayload, FrameType},
    frames::{Ack, AgentDisconnect, AgentHello, FrameCapabilities, HaproxyHello},
};
use std::{os::unix::fs::PermissionsExt, path::Path};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() -> Result<()> {
    let socket_path = "spoa_agent/spoa.sock";

    // Clean up the socket if it already exists
    if Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    // Set permissions to 777 (testing purposes)
    let perms = std::fs::Permissions::from_mode(0o777);
    std::fs::set_permissions(socket_path, perms)?;
    println!("SPOE Agent listening on UNIX socket at {socket_path}");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                println!("New UNIX connection from {stream:?}");
                tokio::spawn(handle_connection(stream));
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {e:?}");
            }
        }
    }
}

async fn handle_connection(u_stream: UnixStream) -> Result<()> {
    let mut socket = Framed::new(u_stream, SpopCodec);

    while let Some(result) = socket.next().await {
        let frame = match result {
            Ok(f) => f,
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

                let max_frame_size = hello.max_frame_size;
                let is_healthcheck = hello.healthcheck.unwrap_or(false);
                // * "version"    <STRING>
                // This is the SPOP version the agent supports. It must follow the format
                // "Major.Minor" and it must be lower or equal than one of major versions
                // announced by HAProxy.
                let version = Version::parse("2.0.0")?;

                // Create the AgentHello with the values
                let agent_hello = AgentHello {
                    version,
                    max_frame_size,
                    capabilities: vec![FrameCapabilities::Pipelining],
                };

                println!("Sending AgentHello: {:#?}", agent_hello.payload());

                match socket.send(agent_hello.into()).await {
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
                let agent_disconnect = AgentDisconnect {
                    status_code: 0,
                    message: "Goodbye".to_string(),
                };

                println!("Sending AgentDisconnect: {:#?}", agent_disconnect.payload());

                socket.send(agent_disconnect.into()).await?;
                socket.close().await?;

                return Ok(());
            }

            // Respond with Ack frame
            FrameType::Notify => {
                if let FramePayload::ListOfMessages(messages) = &frame.payload() {
                    // Create the Ack frame
                    let mut ack = Ack::new(frame.metadata().stream_id, frame.metadata().frame_id);

                    for message in messages {
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
                    socket.send(ack.into()).await?;
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
