use crate::{
    SpopFrame,
    frame::{FrameFlags, FramePayload, FrameType, Metadata},
    types::TypedData,
};
use std::{borrow::Cow, collections::HashMap};

/// Frame AGENT-DISCONNECT
///
/// <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L979>
///
/// ```text
/// 3.2.9. Frame: AGENT-DISCONNECT
/// -------------------------------
///
/// If an error occurs, at anytime, from the agent size, a AGENT-DISCONNECT frame
/// is sent, with information describing the error. such frame is also sent in reply
/// to a HAPROXY-DISCONNECT. The agent must close the socket just after sending
/// this frame.
///
/// The payload of this frame is a KV-LIST. STREAM-ID and FRAME-ID are must be set
/// 0.
///
/// Following items are mandatory in the KV-LIST:
///
///   * "status-code"    <UINT32>
///
///     This is the code corresponding to the error.
///
///   * "message"    <STRING>
///
///     This is a textual message describing the error.
///
/// For more information about known errors, see section "Errors & timeouts"
/// ```
#[derive(Debug)]
pub struct AgentDisconnect {
    pub status_code: u32,
    pub message: String,
}

impl SpopFrame for AgentDisconnect {
    fn frame_type(&self) -> &FrameType {
        &FrameType::AgentDisconnect
    }

    fn metadata(&self) -> Cow<'_, Metadata> {
        Cow::Owned(Metadata {
            flags: FrameFlags::new(true, false), // FIN flag set, ABORT flag not set
            stream_id: 0,
            frame_id: 0,
        })
    }

    fn payload(&self) -> FramePayload<'_> {
        let mut map = HashMap::new();

        map.insert(
            "status-code".to_string(),
            TypedData::UInt32(self.status_code),
        );

        map.insert(
            "message".to_string(),
            TypedData::String(self.message.clone()),
        );

        FramePayload::KVList(map)
    }
}
