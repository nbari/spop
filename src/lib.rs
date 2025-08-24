//! # SPOP Library for parsing HAProxy SPOP (Stream Processing Offload Protocol)
//!
//! <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt>
//!
//! This crate provides structures, traits, and utilities for working with the SPOP protocol frames,
//! including the ability to serialize/deserialize frames and handle various frame types such as
//! `AgentHello`, `HaproxyHello`, and `Ack`. It supports both Unix and TCP-based transports
//! and provides utilities for creating, parsing, and manipulating SPOP frames.
pub mod frames;
pub mod parser;

pub mod actions;
pub use self::actions::{Action, VarScope};

pub mod frame;
pub use self::frame::{FrameFlags, FramePayload, FrameType, Metadata};

pub mod types;
pub use self::types::TypedData;

pub mod varint;
pub use self::varint::{decode_varint, encode_varint};

pub mod codec;
pub use self::codec::SpopCodec;

pub use semver::Version;

/// core trait for the SPOP frame
///
/// <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L673>
///
/// ```text
/// 3.2. Frames
/// ------------
///
/// Exchange between HAProxy and agents are made using FRAME packets. All frames
/// must be prefixed with their size encoded on 4 bytes in network byte order:
///
///     <FRAME-LENGTH:4 bytes> <FRAME>
///
/// A frame always starts with its type, on one byte, followed by metadata
/// containing flags, on 4 bytes and a two variable-length integer representing the
/// stream identifier and the frame identifier inside the stream:
///
///     FRAME       : <FRAME-TYPE:1 byte> <METADATA> <FRAME-PAYLOAD>
///     METADATA    : <FLAGS:4 bytes> <STREAM-ID:varint> <FRAME-ID:varint>
///
/// Then comes the frame payload. Depending on the frame type, the payload can be
/// of three types: a simple key/value list, a list of messages or a list of
/// actions.
///
///     FRAME-PAYLOAD    : <LIST-OF-MESSAGES> | <LIST-OF-ACTIONS> | <KV-LIST>
///
///     LIST-OF-MESSAGES : [ <MESSAGE-NAME> <NB-ARGS:1 byte> <KV-LIST> ... ]
///     MESSAGE-NAME     : <STRING>
///
///     LIST-OF-ACTIONS  : [ <ACTION-TYPE:1 byte> <NB-ARGS:1 byte> <ACTION-ARGS> ... ]
///     ACTION-ARGS      : [ <TYPED-DATA>... ]
///
///     KV-LIST          : [ <KV-NAME> <KV-VALUE> ... ]
///     KV-NAME          : <STRING>
///     KV-VALUE         : <TYPED-DATA>
///
///     FLAGS :
///
///     Flags are a 32 bits field. They are encoded on 4 bytes in network byte
///     order, where the bit 0 is the LSB.
///
///               0   1      2-31
///             +---+---+----------+
///             |   | A |          |
///             | F | B |          |
///             | I | O | RESERVED |
///             | N | R |          |
///             |   | T |          |
///             +---+---+----------+
///
///     FIN: Indicates that this is the final payload fragment. The first fragment
///          may also be the final fragment. The payload fragmentation was removed
///          and is now deprecated. It means the FIN flag must be set on all
///          frames.
///
///     ABORT: Indicates that the processing of the current frame must be
///            cancelled.
///
///
/// Frames cannot exceed a maximum size negotiated between HAProxy and agents
/// during the HELLO handshake. Most of time, payload will be small enough to send
/// it in one frame.
///
/// IMPORTANT : The maximum size supported by peers for a frame must be greater
///             than or equal to 256 bytes. A good common value is the HAProxy
///             buffer size minus 4 bytes, reserved for the frame length
///             (tune.bufsize - 4). It is the default value announced by HAproxy.
/// ```
pub trait SpopFrame: std::fmt::Debug + Send {
    fn frame_type(&self) -> &FrameType;
    fn metadata(&self) -> Metadata;
    fn payload(&self) -> FramePayload;

    fn serialize(&self) -> std::io::Result<Vec<u8>> {
        let mut serialized = Vec::new();

        // frame type (1 byte)
        serialized.push(self.frame_type().to_u8());

        // Metadata
        serialized.extend(self.metadata().serialize());

        // payload
        encode_payload(&self.payload(), &mut serialized)?;

        // Prepend frame length
        let frame_len = serialized.len() as u32;
        let mut output = frame_len.to_be_bytes().to_vec();
        output.extend(serialized);

        Ok(output)
    }
}

impl<'a, T: SpopFrame + Sized + 'a> From<T> for Box<dyn SpopFrame + 'a> {
    fn from(value: T) -> Box<dyn SpopFrame + 'a> {
        Box::new(value)
    }
}

/// Helper function to encode the payload.
/// It supports ListOfActions and KVList payloads.
fn encode_payload(payload: &FramePayload, buf: &mut Vec<u8>) -> std::io::Result<()> {
    match payload {
        FramePayload::ListOfActions(actions) => {
            // ACTION-SET-VAR  : <SET-VAR:1 byte><NB-ARGS:1 byte><VAR-SCOPE:1 byte><VAR-NAME><VAR-VALUE>

            for action in actions {
                match action {
                    Action::SetVar { scope, name, value } => {
                        // Action type: SET-VAR (1 byte)
                        buf.push(0x01);

                        // Number of arguments: 3 (1 byte)
                        buf.push(0x03);

                        // Scope (1 byte)
                        buf.push(scope.to_u8());

                        // Serialize variable name (length + bytes)
                        buf.extend(encode_varint(name.len() as u64));
                        buf.extend_from_slice(name.as_bytes());

                        // Serialize variable value based on type
                        value.to_bytes(buf);
                    }

                    Action::UnSetVar { scope, name } => {
                        // Action type: UNSET-VAR (1 byte)
                        buf.push(0x02);

                        // Number of arguments: 2 (1 byte)
                        buf.push(0x02);

                        // Scope (1 byte)
                        buf.push(scope.to_u8());

                        // Serialize variable name (length + bytes)
                        buf.extend(encode_varint(name.len() as u64));
                        buf.extend_from_slice(name.as_bytes());
                    }
                }
            }
        }

        FramePayload::KVList(kv_pairs) => {
            for (key, value) in kv_pairs {
                // <KEY-LENGTH><KEY><VALUE-TYPE><VALUE-LNGTH><VALUE>

                // use encode_varint for the length of the key
                buf.extend(encode_varint(key.len() as u64));

                // serialize the key
                buf.extend_from_slice(key.as_bytes());

                match value {
                    TypedData::String(val) => {
                        // STRING: <8><LENGTH:varint><BYTES>
                        buf.push(0x08);
                        // use encode_varint for the length of the value
                        buf.extend(encode_varint(val.len() as u64));
                        // serialize the value
                        buf.extend_from_slice(val.as_bytes());
                    }

                    TypedData::UInt32(val) => {
                        // UINT32: <3><VALUE:varint>
                        buf.push(0x03);
                        // use encode_varint for the length of the value
                        buf.extend(encode_varint(*val as u64));
                    }

                    _ => {}
                }
            }
        }

        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported frame payload type",
            ));
        }
    }

    Ok(())
}
