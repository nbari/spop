use crate::{
    SpopFrame,
    actions::{Action, VarScope},
    frame::{FrameFlags, FramePayload, FrameType, Metadata},
    types::TypedData,
};

/// Frame Ack
///
/// <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L949>
///
/// ```text
/// 3.2.7. Frame: ACK
/// ------------------
///
/// ACK frames must be sent by agents to reply to NOTIFY frames. STREAM-ID and
/// FRAME-ID found in a NOTIFY frame must be reuse in the corresponding ACK
/// frame. The payload of ACK frames is a LIST-OF-ACTIONS.
/// ```
#[derive(Debug, Clone)]
pub struct Ack {
    pub stream_id: u64,
    pub frame_id: u64,
    pub actions: Vec<Action>,
}

impl Ack {
    /// Creates a new ACK frame with no actions
    #[must_use]
    pub const fn new(stream_id: u64, frame_id: u64) -> Self {
        Self {
            stream_id,
            frame_id,
            actions: Vec::new(),
        }
    }

    /// Adds a set-var action to the ACK frame
    #[must_use]
    pub fn set_var(mut self, scope: VarScope, name: &str, value: impl Into<TypedData>) -> Self {
        self.actions.push(Action::SetVar {
            scope,
            name: name.to_string(),
            value: value.into(),
        });
        self
    }

    // Adds an unset-var action to the ACK frame
    #[must_use]
    pub fn unset_var(mut self, scope: VarScope, name: &str) -> Self {
        self.actions.push(Action::UnSetVar {
            scope,
            name: name.to_string(),
        });
        self
    }
}

/// Serializes the ACK frame into a `Frame` structure
impl SpopFrame for Ack {
    fn frame_type(&self) -> &FrameType {
        &FrameType::Ack
    }

    fn metadata(&self) -> Metadata {
        Metadata {
            flags: FrameFlags::new(true, false), // FIN flag set, ABORT flag not set
            stream_id: self.stream_id,
            frame_id: self.frame_id,
        }
    }

    fn payload(&self) -> FramePayload {
        FramePayload::ListOfActions(self.actions.clone())
    }
}
