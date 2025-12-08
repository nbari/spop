use crate::{
    SpopFrame,
    frame::{FramePayload, FrameType, Metadata},
    types::TypedData,
};
use std::{collections::HashMap, convert::TryFrom};

/// Frame HAPROXY-DISCONNECT
///
/// <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L956>
///
/// ```text
/// 3.2.8. Frame: HAPROXY-DISCONNECT
/// ---------------------------------
///
/// If an error occurs, at anytime, from the HAProxy side, a HAPROXY-DISCONNECT
/// frame is sent with information describing the error. HAProxy will wait an
/// AGENT-DISCONNECT frame in reply. All other frames will be ignored. The agent
/// must then close the socket.
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
/// ```
#[derive(Debug)]
pub struct HaproxyDisconnect {
    pub status_code: u32,
    pub message: String,
}

impl HaproxyDisconnect {
    #[must_use]
    pub fn to_kv_list(&self) -> HashMap<String, TypedData> {
        let mut map = HashMap::new();

        map.insert(
            "status-code".to_string(),
            TypedData::UInt32(self.status_code),
        );

        map.insert(
            "message".to_string(),
            TypedData::String(self.message.clone()),
        );

        map
    }
}

#[derive(Debug)]
pub struct HaproxyDisconnectFrame {
    pub metadata: Metadata,
    pub payload: HaproxyDisconnect,
}

impl SpopFrame for HaproxyDisconnectFrame {
    fn frame_type(&self) -> &FrameType {
        &FrameType::HaproxyDisconnect
    }

    fn metadata(&self) -> Metadata {
        self.metadata.clone()
    }

    fn payload(&self) -> FramePayload {
        FramePayload::KVList(self.payload.to_kv_list())
    }
}

impl TryFrom<FramePayload> for HaproxyDisconnect {
    type Error = String;

    fn try_from(payload: FramePayload) -> Result<Self, Self::Error> {
        // Ensure that the payload is a KVList
        if let FramePayload::KVList(kv_list) = payload {
            let status_code = kv_list
                .get("status-code")
                .and_then(|v| match v {
                    TypedData::UInt32(val) => Some(*val),
                    _ => None,
                })
                .ok_or_else(|| "Missing or invalid status_code".to_string())?;

            let message = kv_list
                .get("message")
                .and_then(|v| match v {
                    TypedData::String(val) => Some(val.clone()),
                    _ => None,
                })
                .ok_or_else(|| "Missing message".to_string())?;

            Ok(Self {
                status_code,
                message,
            })
        } else {
            Err("Invalid FramePayload type, expected KVList.".to_string())
        }
    }
}
