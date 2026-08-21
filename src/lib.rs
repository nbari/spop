//! # SPOP Library for parsing `HAProxy` SPOP (Stream Processing Offload Protocol)
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

pub mod status;
pub use self::status::StatusCode;

pub mod types;
pub use self::types::TypedData;

pub mod varint;
pub use self::varint::{decode_varint, encode_varint_into, varint_len};

pub mod codec;
pub use self::codec::SpopCodec;

pub use semver::Version;

use std::borrow::Cow;

/// Hard upper bound on the frame size this crate will parse.
///
/// The real limit is negotiated during the HELLO handshake (`max-frame-size`), but the frame
/// length prefix is the first thing read off the socket, before any handshake state exists. It is
/// four bytes wide, so an untrusted peer can claim up to `u32::MAX` — roughly 4 GiB. A frame that
/// large never completes, so the codec never advances the read buffer and it accumulates
/// everything the peer sends, without bound and never reclaimed. The peer has to transmit those
/// bytes to occupy them, so this is memory exhaustion rather than amplification — but the memory
/// is held for as long as the connection lives.
///
/// 1 MiB is chosen from what the protocol actually permits: `max-frame-size` must fall in
/// `[MIN_FRAME_SIZE, tune.bufsize - 4]`, `tune.bufsize` defaults to 16384, and `HAProxy` both
/// defaults to and recommends staying at that value — so the negotiated size is normally 16380.
/// This leaves roughly 64x headroom for an unusually large `tune.bufsize` while keeping
/// worst-case buffering to something a process absorbs without noticing.
///
/// This is a backstop for the pre-handshake window, not enforcement of the agreed limit. Once
/// HAPROXY-HELLO has been parsed, [`crate::frames::HaproxyHello::negotiate_max_frame_size`]
/// gives the value both peers actually settled on, and
/// [`crate::SpopCodec::set_max_frame_size`] applies it.
///
/// `HAProxy` does the same thing with a tighter default: it starts a connection at
/// `tune.bufsize - 4` and narrows to the negotiated value once AGENT-HELLO arrives (see
/// `spop_conn->max_frame_size` in `src/mux_spop.c`). This crate cannot know the peer's
/// `tune.bufsize`, so it starts looser — an agent that never calls `set_max_frame_size` stays
/// safe rather than rejecting frames a peer with a raised `tune.bufsize` may legitimately send.
pub const MAX_FRAME_SIZE_LIMIT: u32 = 1024 * 1024;

/// The SPOP version this crate implements.
///
/// `HAProxy` announces only `2.0` (see `spop_supported_versions` in `src/mux_spop.c`); support
/// for `1.0` was dropped over a bug in the handling of frame flags. Only `major.minor` travels
/// on the wire, so the patch component is never transmitted.
pub const SUPPORTED_VERSION: Version = Version::new(2, 0, 0);

/// Smallest `max-frame-size` the protocol permits a peer to announce.
///
/// > IMPORTANT : The maximum size supported by peers for a frame must be greater
/// >             than or equal to 256 bytes.
pub const MIN_FRAME_SIZE: u32 = 256;

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
    fn metadata(&self) -> Cow<'_, Metadata>;
    fn payload(&self) -> FramePayload<'_>;

    /// Serializes the frame into a freshly allocated buffer.
    ///
    /// Prefer [`SpopFrame::serialize_into`] when a destination buffer already exists: it writes
    /// the frame in place instead of allocating and then copying.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or if the payload type is unsupported.
    fn serialize(&self) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        write_frame(self, &mut buf)?;
        Ok(buf)
    }

    /// Serializes the frame by appending it to an existing buffer.
    ///
    /// Reusing one buffer across frames means no per-frame allocation, which is what
    /// [`crate::SpopCodec`] does. [`SpopFrame::serialize`] allocates a fresh `Vec` every call.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or if the payload type is unsupported.
    fn serialize_into(&self, dst: &mut Vec<u8>) -> std::io::Result<()> {
        write_frame(self, dst)
    }
}

/// Shared implementation behind [`SpopFrame::serialize`] and [`SpopFrame::serialize_into`].
///
/// A free function rather than a trait method: a generic method would make `SpopFrame`
/// non-object-safe and break `Box<dyn SpopFrame>`, and the `where Self: Sized` escape hatch
/// would make it uncallable from the object-safe defaults above. Generic over `F: ?Sized` so it
/// works for both concrete frames and `dyn SpopFrame`.
#[allow(clippy::cast_possible_truncation)]
fn write_frame<F>(frame: &F, dst: &mut Vec<u8>) -> std::io::Result<()>
where
    F: SpopFrame + ?Sized,
{
    let metadata = frame.metadata();
    let payload = frame.payload();
    let frame_len = 1 + metadata.serialized_len() + payload_serialized_len(&payload)?;

    // Size the destination once so a frame is never written across a reallocation.
    dst.reserve(4 + frame_len);

    // Frame length prefix (4 bytes, network byte order)
    dst.extend_from_slice(&(frame_len as u32).to_be_bytes());

    // frame type (1 byte)
    dst.push(frame.frame_type().to_u8());

    // Metadata
    metadata.write_to(dst);

    // payload
    encode_payload(&payload, dst)?;

    Ok(())
}

impl<'a, T: SpopFrame + Sized + 'a> From<T> for Box<dyn SpopFrame + 'a> {
    fn from(value: T) -> Self {
        Box::new(value)
    }
}

/// Helper function to encode the payload.
/// It supports `ListOfActions` and `KVList` payloads.
#[allow(clippy::cast_possible_truncation)]
fn encode_payload(payload: &FramePayload, buf: &mut Vec<u8>) -> std::io::Result<()> {
    match payload {
        FramePayload::ListOfActions(actions) => {
            // ACTION-SET-VAR  : <SET-VAR:1 byte><NB-ARGS:1 byte><VAR-SCOPE:1 byte><VAR-NAME><VAR-VALUE>

            for action in *actions {
                match action {
                    Action::SetVar { scope, name, value } => {
                        // SET-VAR (1 byte), NB-ARGS = 3 (1 byte), VAR-SCOPE (1 byte)
                        buf.extend_from_slice(&[0x01, 0x03, scope.to_u8()]);

                        // Serialize variable name (length + bytes)
                        varint::encode_varint_into(name.len() as u64, buf);
                        buf.extend_from_slice(name.as_bytes());

                        // Serialize variable value based on type
                        value.to_bytes(buf);
                    }

                    Action::UnSetVar { scope, name } => {
                        // UNSET-VAR (1 byte), NB-ARGS = 2 (1 byte), VAR-SCOPE (1 byte)
                        buf.extend_from_slice(&[0x02, 0x02, scope.to_u8()]);

                        // Serialize variable name (length + bytes)
                        varint::encode_varint_into(name.len() as u64, buf);
                        buf.extend_from_slice(name.as_bytes());
                    }
                }
            }
        }

        FramePayload::KVList(kv_pairs) => {
            for (key, value) in kv_pairs {
                // <KV-NAME><KV-VALUE>, where KV-VALUE is a full TYPED-DATA

                // KV-NAME is a <STRING>: length prefix then bytes
                varint::encode_varint_into(key.len() as u64, buf);
                buf.extend_from_slice(key.as_bytes());

                // KV-VALUE is a <TYPED-DATA>. Delegating to TypedData covers all ten wire types
                // and stays in lockstep with `TypedData::serialized_len`, which is what keeps the
                // frame length prefix correct.
                value.to_bytes(buf);
            }
        }

        FramePayload::ListOfMessages(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported frame payload type",
            ));
        }
    }

    Ok(())
}

fn payload_serialized_len(payload: &FramePayload) -> std::io::Result<usize> {
    match payload {
        FramePayload::ListOfActions(actions) => Ok(actions
            .iter()
            .map(|action| match action {
                Action::SetVar { name, value, .. } => {
                    3 + varint::varint_len(name.len() as u64) + name.len() + value.serialized_len()
                }
                Action::UnSetVar { name, .. } => {
                    3 + varint::varint_len(name.len() as u64) + name.len()
                }
            })
            .sum()),
        FramePayload::KVList(kv_pairs) => Ok(kv_pairs
            .iter()
            .map(|(key, value)| {
                varint::varint_len(key.len() as u64) + key.len() + value.serialized_len()
            })
            .sum()),
        FramePayload::ListOfMessages(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Unsupported frame payload type",
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::frames::FrameCapabilities;
    use crate::frames::haproxy_hello::{HaproxyHello, HaproxyHelloFrame};
    use crate::types::typed_data;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Reads the 4-byte big-endian frame length prefix.
    fn declared_frame_len(frame: &[u8]) -> usize {
        let prefix: [u8; 4] = frame
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .expect("frame has a length prefix");
        u32::from_be_bytes(prefix) as usize
    }

    fn every_typed_data() -> Vec<(&'static str, TypedData)> {
        vec![
            ("null", TypedData::Null),
            ("bool-true", TypedData::Bool(true)),
            ("bool-false", TypedData::Bool(false)),
            ("int32", TypedData::Int32(-42)),
            ("uint32", TypedData::UInt32(4_000_000_000)),
            ("int64", TypedData::Int64(-9_000_000_000)),
            ("uint64", TypedData::UInt64(u64::MAX)),
            ("ipv4", TypedData::IPv4(Ipv4Addr::new(192, 0, 2, 1))),
            ("ipv6", TypedData::IPv6(Ipv6Addr::LOCALHOST)),
            ("string", TypedData::String("tequila".to_string())),
            ("binary", TypedData::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF])),
        ]
    }

    /// The KV-LIST encoder used to handle only `String` and `UInt32`, emitting a key with **no
    /// value** for the other eight types — including the Bool that HAPROXY-HELLO carries.
    /// `payload_serialized_len` mirrored the same gap, so the length prefix stayed
    /// self-consistent and nothing failed loudly.
    #[test]
    fn test_kv_list_encodes_every_typed_data_variant() {
        for (key, value) in every_typed_data() {
            let mut map = HashMap::new();
            map.insert(key.to_string(), value.clone());
            let payload = FramePayload::KVList(map);

            let mut buf = Vec::new();
            encode_payload(&payload, &mut buf).expect("encode");

            // The length pass must agree with what the encode pass actually wrote, otherwise
            // every frame carrying this value gets a wrong length prefix.
            assert_eq!(
                buf.len(),
                payload_serialized_len(&payload).expect("len"),
                "serialized_len disagrees with encode_payload for {key}"
            );

            // And the bytes must decode back to the same value.
            let (rest, name_len) = varint::decode_varint(&buf).expect("key length");
            let name_len = usize::try_from(name_len).expect("key length fits");
            let (name, rest) = rest.split_at(name_len);
            assert_eq!(std::str::from_utf8(name).expect("utf8"), key);

            let (rest, decoded) = typed_data(rest).expect("typed data");
            assert_eq!(decoded, value, "{key} did not survive the round trip");
            assert!(rest.is_empty(), "trailing bytes after {key}");
        }
    }

    /// End-to-end: HAPROXY-HELLO carries `healthcheck` as a Bool, which the old encoder dropped.
    #[test]
    fn test_haproxy_hello_round_trips_through_the_parser() {
        let hello = HaproxyHello {
            supported_versions: vec![SUPPORTED_VERSION.clone()],
            max_frame_size: 16380,
            capabilities: vec![FrameCapabilities::Pipelining],
            healthcheck: Some(true),
            engine_id: Some("engine-1".to_string()),
        };

        let frame = HaproxyHelloFrame {
            metadata: Metadata {
                flags: FrameFlags::new(true, false),
                stream_id: 0,
                frame_id: 0,
            },
            payload: hello,
        };

        let bytes = frame.serialize().expect("serialize");
        let (rest, parsed) = parser::parse_frame(&bytes).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(*parsed.frame_type(), FrameType::HaproxyHello);

        let FramePayload::KVList(kv) = parsed.payload() else {
            panic!("expected a KV-LIST payload");
        };
        let round_tripped = HaproxyHello::try_from(FramePayload::KVList(kv)).expect("try_from");

        assert_eq!(round_tripped.healthcheck, Some(true));
        assert_eq!(round_tripped.max_frame_size, 16380);
        assert_eq!(round_tripped.engine_id.as_deref(), Some("engine-1"));
        assert_eq!(round_tripped.supported_versions, vec![SUPPORTED_VERSION]);
        assert_eq!(
            round_tripped.capabilities,
            vec![FrameCapabilities::Pipelining]
        );

        // `serialize_into` must produce an equivalent frame. Byte-identity cannot be asserted
        // here: `FramePayload::KVList` is a HashMap, so each `payload()` call emits the pairs in
        // a different order. Ordering is protocol-legal, hence a logical comparison.
        let mut via_codec = Vec::new();
        frame
            .serialize_into(&mut via_codec)
            .expect("serialize_into");
        assert_eq!(via_codec.len(), bytes.len());

        let (_, reparsed) = parser::parse_frame(&via_codec).expect("parse serialize_into output");
        let FramePayload::KVList(kv2) = reparsed.payload() else {
            panic!("expected a KV-LIST payload");
        };
        let from_codec = HaproxyHello::try_from(FramePayload::KVList(kv2)).expect("try_from");
        assert_eq!(from_codec.healthcheck, Some(true));
        assert_eq!(from_codec.max_frame_size, 16380);
    }

    /// `serialize_into` must write exactly what `serialize` produces. ACK carries a
    /// `ListOfActions`, which is a Vec, so the byte order is deterministic here.
    #[test]
    fn test_serialize_into_matches_serialize() {
        let ack = crate::frames::Ack::new(7, 42)
            .set_var(actions::VarScope::Session, "ip_score", 99u32)
            .set_var(actions::VarScope::Transaction, "my_var", "tequila")
            .unset_var(actions::VarScope::Request, "gone");

        let via_vec = ack.serialize().expect("serialize");

        let mut via_bytes = Vec::new();
        ack.serialize_into(&mut via_bytes).expect("serialize_into");

        assert_eq!(&via_bytes[..], &via_vec[..]);

        // And the declared length must match the bytes actually written.
        assert_eq!(declared_frame_len(&via_vec), via_vec.len() - 4);
    }

    /// The negotiation helpers added in this release.
    #[test]
    fn test_negotiation_helpers() {
        let compatible = HaproxyHello {
            supported_versions: vec![SUPPORTED_VERSION.clone()],
            max_frame_size: 16380,
            capabilities: vec![],
            healthcheck: None,
            engine_id: None,
        };
        assert_eq!(compatible.negotiate_version(), Some(SUPPORTED_VERSION));
        assert_eq!(
            compatible.negotiate_max_frame_size(MAX_FRAME_SIZE_LIMIT),
            Ok(16380)
        );
        // We never announce more than HAProxy offered.
        assert_eq!(compatible.negotiate_max_frame_size(1024), Ok(1024));

        // HAProxy dropped SPOP 1.0; nothing compatible on offer means no reply version.
        let stale = HaproxyHello {
            supported_versions: vec![Version::new(1, 0, 0)],
            max_frame_size: 16380,
            capabilities: vec![],
            healthcheck: None,
            engine_id: None,
        };
        assert_eq!(stale.negotiate_version(), None);

        // Below the 256-byte floor the spec mandates.
        let tiny = HaproxyHello {
            supported_versions: vec![SUPPORTED_VERSION.clone()],
            max_frame_size: 128,
            capabilities: vec![],
            healthcheck: None,
            engine_id: None,
        };
        assert_eq!(
            tiny.negotiate_max_frame_size(MAX_FRAME_SIZE_LIMIT),
            Err(StatusCode::BadFrameSize)
        );
    }
}
