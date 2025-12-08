use crate::{actions::Action, types::TypedData, varint::encode_varint};
use nom::error::ErrorKind;
use std::collections::HashMap;

/// <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L751>
///
/// ```text
/// 3.2.2. Frame types overview
/// ----------------------------
///
/// Here are types of frame supported by SPOE. Frames sent by HAProxy come first,
/// then frames sent by agents :
///
///     TYPE                       |  ID | DESCRIPTION
///   -----------------------------+-----+-------------------------------------
///      HAPROXY-HELLO             |  1  |  Sent by HAProxy when it opens a
///                                |     |  connection on an agent.
///                                |     |
///      HAPROXY-DISCONNECT        |  2  |  Sent by HAProxy when it want to close
///                                |     |  the connection or in reply to an
///                                |     |  AGENT-DISCONNECT frame
///                                |     |
///      NOTIFY                    |  3  |  Sent by HAProxy to pass information
///                                |     |  to an agent
///   -----------------------------+-----+-------------------------------------
///      AGENT-HELLO               | 101 |  Reply to a HAPROXY-HELLO frame, when
///                                |     |  the connection is established
///                                |     |
///      AGENT-DISCONNECT          | 102 |  Sent by an agent just before closing
///                                |     |  the connection
///                                |     |
///      ACK                       | 103 |  Sent to acknowledge a NOTIFY frame
///   -----------------------------+-----+-------------------------------------
/// ```
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum FrameType {
    HaproxyHello = 1,
    HaproxyDisconnect = 2,
    Notify = 3,
    AgentHello = 101,
    AgentDisconnect = 102,
    Ack = 103,
}

impl FrameType {
    /// # Errors
    ///
    /// Returns an error if the value doesn't correspond to a valid frame type.
    pub const fn from_u8(value: u8) -> Result<Self, ErrorKind> {
        match value {
            1 => Ok(Self::HaproxyHello),
            2 => Ok(Self::HaproxyDisconnect),
            3 => Ok(Self::Notify),
            101 => Ok(Self::AgentHello),
            102 => Ok(Self::AgentDisconnect),
            103 => Ok(Self::Ack),
            _ => Err(ErrorKind::Alt),
        }
    }

    /// Converts `FrameType` to its corresponding u8 value
    #[must_use]
    pub const fn to_u8(&self) -> u8 {
        match self {
            Self::HaproxyHello => 1,
            Self::HaproxyDisconnect => 2,
            Self::Notify => 3,
            Self::AgentHello => 101,
            Self::AgentDisconnect => 102,
            Self::Ack => 103,
        }
    }

    /// Converts `FrameType` to its str representation
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HaproxyHello => "HAPROXY-HELLO",
            Self::HaproxyDisconnect => "HAPROXY-DISCONNECT",
            Self::Notify => "NOTIFY",
            Self::AgentHello => "AGENT-HELLO",
            Self::AgentDisconnect => "AGENT-DISCONNECT",
            Self::Ack => "ACK",
        }
    }
}

///  metadata contanis flags, on 4 bytes and a two variable-length integer representing the
///  stream identifier and the frame identifier inside the stream:
///
/// ```text
/// METADATA    : <FLAGS:4 bytes> <STREAM-ID:varint> <FRAME-ID:varint>
/// ```
#[derive(Debug, Clone, Default)]
pub struct Metadata {
    pub flags: FrameFlags,
    pub stream_id: u64,
    pub frame_id: u64,
}

impl Metadata {
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        // Serialize flags (4 bytes)
        serialized.extend_from_slice(&self.flags.to_be_bytes());

        // Serialize stream_id and frame_id (both encoded as varint)
        serialized.extend(encode_varint(self.stream_id));
        serialized.extend(encode_varint(self.frame_id));

        serialized
    }
}

/// Then comes the frame payload. Depending on the frame type, the payload can be
/// of three types: a simple key/value list, a list of messages or a list of
/// actions.
/// ```text
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
/// ```
#[derive(Debug)]
pub enum FramePayload {
    ListOfMessages(Vec<Message>),
    ListOfActions(Vec<Action>),
    KVList(HashMap<String, TypedData>),
}

/// Represents a message in the list of messages.
/// ```text
///     LIST-OF-MESSAGES : [ <MESSAGE-NAME> <NB-ARGS:1 byte> <KV-LIST> ... ]
///     MESSAGE-NAME     : <STRING>
/// ```
#[derive(Debug, Clone)]
pub struct Message {
    pub name: String,
    pub args: HashMap<String, TypedData>,
}

/// Flags are a 32 bits field. They are encoded on 4 bytes in network byte
/// order, where the bit 0 is the LSB.
///
/// ```text
/// FLAGS :
///
///           0   1      2-31
///         +---+---+----------+
///         |   | A |          |
///         | F | B |          |
///         | I | O | RESERVED |
///         | N | R |          |
///         |   | T |          |
///         +---+---+----------+
///
/// FIN: Indicates that this is the final payload fragment. The first fragment
///      may also be the final fragment. The payload fragmentation was removed
///      and is now deprecated. It means the FIN flag must be set on all
///      frames.
///
/// ABORT: Indicates that the processing of the current frame must be
///        cancelled.
/// ```
#[derive(Debug, Clone, Default)]
pub struct FrameFlags(u32);

impl FrameFlags {
    #[must_use]
    pub const fn new(is_fin: bool, is_abort: bool) -> Self {
        let mut flags = 0u32;

        if is_fin {
            flags |= 0x0000_0001;
        }

        if is_abort {
            flags |= 0x0000_0002;
        }

        Self(flags)
    }

    #[must_use]
    pub const fn is_fin(&self) -> bool {
        self.0 & 0x0000_0001_u32 != 0
    }

    #[must_use]
    pub const fn is_abort(&self) -> bool {
        self.0 & 0x0000_0002_u32 != 0
    }

    /// Parses `FrameFlags` from a 4-byte network order field
    ///
    /// # Errors
    ///
    /// Returns an error if the flags are invalid according to the SPOP protocol.
    pub const fn from_u32(value: u32) -> Result<Self, ErrorKind> {
        // Ensure FIN is always set (per protocol spec)
        if value & 0x0000_0001 == 0 {
            return Err(ErrorKind::Verify); // Equivalent to "validation failed"
        }

        // Ensure only valid bits are set (optional strict check)
        if value & 0xFFFF_FFFC != 0 {
            return Err(ErrorKind::Alt); // Invalid reserved bits used
        }

        Ok(Self(value))
    }

    #[must_use]
    pub const fn to_be_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_from_u8() {
        assert_eq!(FrameType::from_u8(0), Err(ErrorKind::Alt));
        assert_eq!(FrameType::from_u8(1), Ok(FrameType::HaproxyHello));
        assert_eq!(FrameType::from_u8(2), Ok(FrameType::HaproxyDisconnect));
        assert_eq!(FrameType::from_u8(3), Ok(FrameType::Notify));
        assert_eq!(FrameType::from_u8(101), Ok(FrameType::AgentHello));
        assert_eq!(FrameType::from_u8(102), Ok(FrameType::AgentDisconnect));
        assert_eq!(FrameType::from_u8(103), Ok(FrameType::Ack));
    }

    #[test]
    fn test_frame_type_to_u8() {
        assert_eq!(FrameType::HaproxyHello.to_u8(), 1);
        assert_eq!(FrameType::HaproxyDisconnect.to_u8(), 2);
        assert_eq!(FrameType::Notify.to_u8(), 3);
        assert_eq!(FrameType::AgentHello.to_u8(), 101);
        assert_eq!(FrameType::AgentDisconnect.to_u8(), 102);
        assert_eq!(FrameType::Ack.to_u8(), 103);
    }

    #[test]
    fn test_frame_type_as_str() {
        assert_eq!(FrameType::HaproxyHello.as_str(), "HAPROXY-HELLO");
    }

    #[test]
    fn test_frameflags() {
        let flags = FrameFlags(0x00000001);
        assert!(flags.is_fin());

        let flags = FrameFlags(0x00000000);
        assert!(!flags.is_fin());

        let flags = FrameFlags(0x00000002);
        assert!(flags.is_abort());

        let flags = FrameFlags(0x00000003);
        assert!(flags.is_fin());
        assert!(flags.is_abort());
    }

    #[test]
    fn test_frameflags_new() {
        let flags = FrameFlags::new(true, false);
        assert_eq!(flags.0, 0x00000001);

        let flags = FrameFlags::new(false, true);
        assert_eq!(flags.0, 0x00000002);

        let flags = FrameFlags::new(true, true);
        assert_eq!(flags.0, 0x00000003);
    }
}
