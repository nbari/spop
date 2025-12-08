use crate::{
    SpopFrame,
    frame::{FrameFlags, FramePayload, FrameType, Metadata},
    frames::capabilities::FrameCapabilities,
    types::TypedData,
};
use semver::Version;
use std::collections::HashMap;

/// Frame AGENT-HELLO
///
/// <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L905>
///
/// ```text
/// 3.2.5. Frame: AGENT-HELLO
/// --------------------------
///
/// This frame is sent in reply to a HAPROXY-HELLO frame to finish a HELLO
/// handshake. As for HAPROXY-HELLO frame, STREAM-ID and FRAME-ID are also set
/// 0. The payload of this frame is a KV-LIST.
///
/// Following items are mandatory in the KV-LIST:
///
///   * "version"    <STRING>
///
///     This is the SPOP version the agent supports. It must follow the format
///     "Major.Minor" and it must be lower or equal than one of major versions
///     announced by HAProxy.
///
///   * "max-frame-size"    <UINT32>
///
///     This is the maximum size allowed for a frame. It must be lower or equal to
///     the value in the HAPROXY-HELLO frame. This value will be used for all
///     subsequent frames.
///
///   * "capabilities"    <STRING>
///
///     This a comma-separated list of capabilities supported by agent. Spaces must
///     be ignored, if any.
///
/// At this time, if everything is ok for HAProxy (supported version and valid
/// max-frame-size value), the HELLO handshake is successfully completed. Else,
/// HAProxy sends a HAPROXY-DISCONNECT frame with the corresponding error.
///
/// If "healthcheck" item was set to TRUE in the HAPROXY-HELLO frame, the agent can
/// safely close the connection without DISCONNECT frame. In all cases, HAProxy
/// will close the connection at the end of the health check.
/// ```
#[derive(Debug)]
pub struct AgentHello {
    pub version: Version,
    pub max_frame_size: u32,
    pub capabilities: Vec<FrameCapabilities>,
}

impl SpopFrame for AgentHello {
    fn frame_type(&self) -> &FrameType {
        &FrameType::AgentHello
    }

    fn metadata(&self) -> Metadata {
        Metadata {
            flags: FrameFlags::new(true, false), // FIN flag set, ABORT flag not set
            stream_id: 0,
            frame_id: 0,
        }
    }

    fn payload(&self) -> FramePayload {
        let mut map = HashMap::new();

        let version_str = format!("{}.{}", self.version.major, self.version.minor);
        map.insert("version".to_string(), TypedData::String(version_str));

        map.insert(
            "max-frame-size".to_string(),
            TypedData::UInt32(self.max_frame_size),
        );

        let caps_string = self
            .capabilities
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        map.insert("capabilities".into(), TypedData::String(caps_string));

        FramePayload::KVList(map)
    }
}
