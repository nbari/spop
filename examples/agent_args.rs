//! An SPOA that reads its message arguments back, exercising what changed in 0.13.0:
//!
//! - arguments keep their declaration order, and unnamed ones (`args src dst`) arrive with an
//!   empty name, so position is the only thing that tells them apart;
//! - `Message::get` returns the first argument with a given name, so a repeated name resolves
//!   to its first occurrence;
//! - names that are not valid UTF-8 are decoded lossily, with U+FFFD in place of the bad bytes;
//! - decode errors are short: the error kind and the byte offset, never the buffered input.
//!
//! It answers the `echo-args` message from `spoe-test.conf` by setting `txn.spoe_args.summary`
//! to what it decoded: the lookups, the unnamed arguments, and every argument in order.
//! `haproxy.cfg` returns that in the `X-SPOE-ARGS` response header, and
//! `scripts/integration.sh` compares it against what `HAProxy` was configured to send.
use anyhow::Result;
use futures::{SinkExt, StreamExt};
use spop::{
    MAX_FRAME_SIZE_LIMIT, SpopCodec, StatusCode, TypedData,
    actions::VarScope,
    frame::{FramePayload, FrameType, Message},
    frames::{Ack, AgentDisconnect, AgentHello, FrameCapabilities, HaproxyHello},
};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:12346").await?;
    println!("SPOE Agent listening on port 12346...");

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("New connection from {addr}");
        tokio::spawn(handle_connection(stream));
    }
}

/// Renders a value for the summary.
fn render(value: &TypedData) -> String {
    match value {
        TypedData::Null => "null".to_string(),
        TypedData::Bool(b) => b.to_string(),
        TypedData::Int32(n) => n.to_string(),
        TypedData::UInt32(n) => n.to_string(),
        TypedData::Int64(n) => n.to_string(),
        TypedData::UInt64(n) => n.to_string(),
        TypedData::IPv4(ip) => ip.to_string(),
        TypedData::IPv6(ip) => ip.to_string(),
        TypedData::String(s) => s.clone(),
        TypedData::Binary(bytes) => format!("{} bytes", bytes.len()),
    }
}

/// Describes the arguments of `echo-args`, as declared in `spoe-test.conf`:
///
/// ```text
/// args answer=int(42) str(first) src country=hdr(CF-IPCountry) country=str(shadowed)
///      str(second) bad\xff=str(lossy)
/// ```
fn summarize(message: &Message) -> String {
    let named = |name: &str| {
        message
            .get(name)
            .map_or_else(|| "missing".to_string(), render)
    };

    // `country` is declared twice; `get` returns the first, the CF-IPCountry header, not the
    // `str(shadowed)` declared after it.
    let country = named("country");

    // `\xff` is not valid UTF-8, so the name arrives with U+FFFD in its place.
    let lossy = named("bad\u{FFFD}");

    // Unnamed arguments all have an empty name; their order is the order they were declared in.
    let unnamed: Vec<String> = message
        .args
        .iter()
        .filter(|(name, _)| name.is_empty())
        .map(|(_, value)| render(value))
        .collect();

    // Every argument as `name:value`, in the order received, so the whole list is checked and
    // not just what the lookups above reach: the later `country` is still there, for one.
    // `escape_default` keeps the header ASCII, turning U+FFFD into `\u{fffd}`. The separators
    // are unambiguous only because no value in this fixture contains `,` or `:`.
    let all: Vec<String> = message
        .args
        .iter()
        .map(|(name, value)| format!("{}:{}", name.escape_default(), render(value)))
        .collect();

    format!(
        "answer={} country={country} lossy={lossy} unnamed={} all={}",
        named("answer"),
        unnamed.join(","),
        all.join(",")
    )
}

/// Sends an AGENT-DISCONNECT carrying `status` and closes the connection.
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

async fn handle_connection(stream: TcpStream) -> Result<()> {
    let mut socket = Framed::new(stream, SpopCodec::default());

    while let Some(result) = socket.next().await {
        let frame = match result {
            Ok(f) => f,
            // HAProxy closes the connection abruptly at the end of an `option spop-check`
            // health check and when it retires an idle connection: a normal end of life.
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
            // The message names the error kind and where it happened, e.g.
            // "Failed to parse frame: Alt at byte 4", and stays short however large the
            // offending frame was.
            Err(e) => {
                eprintln!("Frame read error: {e}");
                break;
            }
        };

        match frame.frame_type() {
            FrameType::HaproxyHello => {
                let hello = HaproxyHello::try_from(frame.payload())
                    .map_err(|_| anyhow::anyhow!("Failed to parse HaproxyHello"))?;

                let Some(version) = hello.negotiate_version() else {
                    return disconnect(&mut socket, StatusCode::BadVersion).await;
                };

                let max_frame_size = match hello.negotiate_max_frame_size(MAX_FRAME_SIZE_LIMIT) {
                    Ok(size) => size,
                    Err(status) => return disconnect(&mut socket, status).await,
                };

                // Hold the peer to what was agreed; this also bounds how much a single frame
                // can make the agent allocate once decoded.
                socket.codec_mut().set_max_frame_size(max_frame_size);

                let agent_hello = AgentHello {
                    version,
                    max_frame_size,
                    capabilities: vec![FrameCapabilities::Pipelining],
                };
                socket.send(Box::new(agent_hello)).await?;

                if hello.healthcheck.unwrap_or(false) {
                    return Ok(());
                }
            }

            FrameType::HaproxyDisconnect => {
                return disconnect(&mut socket, StatusCode::None).await;
            }

            FrameType::Notify => {
                if let FramePayload::ListOfMessages(messages) = &frame.payload() {
                    let mut ack = Ack::new(frame.metadata().stream_id, frame.metadata().frame_id);

                    for message in *messages {
                        if message.name != "echo-args" {
                            eprintln!("Unsupported message: {:?}", message.name);
                            continue;
                        }

                        // Arguments in the order HAProxy sent them; unnamed ones show as "".
                        for (index, (name, value)) in message.args.iter().enumerate() {
                            println!("  #{index} {name:?} = {value:?}");
                        }

                        let summary = summarize(message);
                        println!("Summary: {summary}");
                        ack = ack.set_var(VarScope::Transaction, "summary", summary);
                    }

                    socket.send(Box::new(ack)).await?;
                }
            }

            _ => {
                eprintln!("Unsupported frame type: {:?}", frame.frame_type());
            }
        }
    }

    Ok(())
}
