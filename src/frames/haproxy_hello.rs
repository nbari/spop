use crate::{
    SpopFrame,
    frame::{FramePayload, FrameType, Metadata},
    frames::capabilities::FrameCapabilities,
    types::TypedData,
};
use semver::Version;
use std::{collections::HashMap, convert::TryFrom, str::FromStr};

/// Frame HAPROXY-HELLO
///
/// <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L860>
///
/// ```text
/// 3.2.4. Frame: HAPROXY-HELLO
/// ----------------------------
///
/// This frame is the first one exchanged between HAProxy and an agent, when the
/// connection is established. The payload of this frame is a KV-LIST. STREAM-ID
/// and FRAME-ID are must be set 0.
///
/// Following items are mandatory in the KV-LIST:
///
///   * "supported-versions"    <STRING>
///
///     Last SPOP major versions supported by HAProxy. It is a comma-separated list
///     of versions, following the format "Major.Minor". Spaces must be ignored, if
///     any. When a major version is announced by HAProxy, it means it also support
///     all previous minor versions.
///
///     Example: "2.0, 1.5" means HAProxy supports SPOP 2.0 and 1.0 to 1.5
///
///   * "max-frame-size"    <UINT32>
///
///     This is the maximum size allowed for a frame. The HAPROXY-HELLO frame must
///     be lower or equal to this value.
///
///   * "capabilities"    <STRING>
///
///     This a comma-separated list of capabilities supported by HAProxy. Spaces
///     must be ignored, if any.
///
/// Following optional items can be added in the KV-LIST:
///
///   * "healthcheck"    <BOOLEAN>
///
///     If this item is set to TRUE, then the HAPROXY-HELLO frame is sent during a
///     SPOE health check. When set to FALSE, this item can be ignored.
///
///   * "engine-id"    <STRING>
///
///     This is a uniq string that identify a SPOE engine.
///
/// To finish the HELLO handshake, the agent must return an AGENT-HELLO frame with
/// its supported SPOP version, the lower value between its maximum size allowed
/// for a frame and the HAProxy one and capabilities it supports. If an error
/// occurs or if an incompatibility is detected with the agent configuration, an
/// AGENT-DISCONNECT frame must be returned.
/// ```
#[derive(Debug)]
pub struct HaproxyHello {
    pub supported_versions: Vec<Version>,
    pub max_frame_size: u32,
    pub capabilities: Vec<FrameCapabilities>,
    pub healthcheck: Option<bool>,
    pub engine_id: Option<String>,
}

impl HaproxyHello {
    pub fn to_kv_list(&self) -> HashMap<String, TypedData> {
        let mut map = HashMap::new();

        let version_str = self
            .supported_versions
            .iter()
            .map(|v| format!("{}.{}", v.major, v.minor)) // skip patch
            .collect::<Vec<_>>()
            .join(", ");

        map.insert(
            "supported-versions".to_string(),
            TypedData::String(version_str),
        );

        map.insert(
            "max-frame-size".to_string(),
            TypedData::UInt32(self.max_frame_size),
        );

        let caps_string = self
            .capabilities
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        map.insert("capabilities".into(), TypedData::String(caps_string));

        if let Some(healthcheck) = self.healthcheck {
            map.insert("healthcheck".to_string(), TypedData::Bool(healthcheck));
        }

        if let Some(ref engine_id) = self.engine_id {
            map.insert(
                "engine-id".to_string(),
                TypedData::String(engine_id.clone()),
            );
        }

        map
    }
}

#[derive(Debug)]
pub struct HaproxyHelloFrame {
    pub metadata: Metadata,
    pub payload: HaproxyHello,
}

impl SpopFrame for HaproxyHelloFrame {
    fn frame_type(&self) -> &FrameType {
        &FrameType::HaproxyHello
    }

    fn metadata(&self) -> Metadata {
        self.metadata.clone()
    }

    fn payload(&self) -> FramePayload {
        FramePayload::KVList(self.payload.to_kv_list())
    }
}

impl TryFrom<FramePayload> for HaproxyHello {
    type Error = String;

    fn try_from(payload: FramePayload) -> Result<Self, Self::Error> {
        // Ensure that the payload is a KVList
        if let FramePayload::KVList(kv_list) = payload {
            let supported_versions = kv_list
                .get("supported-versions")
                .and_then(|v| match v {
                    TypedData::String(v) => Some(
                        v.split(',')
                            .map(|s| {
                                let trimmed = s.trim();
                                let padded = if trimmed.matches('.').count() == 1 {
                                    format!("{trimmed}.0")
                                } else {
                                    trimmed.to_string()
                                };
                                Version::parse(&padded)
                                    .map_err(|e| format!("Invalid version '{trimmed}': {e}"))
                            })
                            .collect::<Result<Vec<_>, _>>(),
                    ),
                    _ => None,
                })
                .ok_or_else(|| "Missing or invalid supported_versions".to_string())?;

            let max_frame_size = kv_list
                .get("max-frame-size")
                .and_then(|v| match v {
                    TypedData::UInt32(val) => Some(*val),
                    _ => None,
                })
                .ok_or_else(|| "Missing or invalid max_frame_size".to_string())?;

            let capabilities = kv_list
                .get("capabilities")
                .and_then(|v| match v {
                    TypedData::String(v) => Some(
                        v.split(',')
                            .map(|s| s.trim())
                            .filter_map(|s| FrameCapabilities::from_str(s).ok())
                            .collect::<Vec<FrameCapabilities>>(),
                    ),
                    _ => None,
                })
                .ok_or_else(|| "Missing or invalid capabilities".to_string())?;

            let healthcheck = kv_list.get("healthcheck").and_then(|v| {
                if let TypedData::Bool(val) = v {
                    Some(*val)
                } else {
                    None
                }
            });

            let engine_id = kv_list.get("engine-id").and_then(|v| {
                if let TypedData::String(val) = v {
                    Some(val.clone())
                } else {
                    None
                }
            });

            Ok(Self {
                supported_versions: supported_versions?,
                max_frame_size,
                capabilities,
                healthcheck,
                engine_id,
            })
        } else {
            Err("Invalid FramePayload type, expected KVList.".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semver::Version;
    use std::any::Any;
    use std::any::TypeId;

    #[test]
    fn test_haproxy_hello_frame() {
        let payload = HaproxyHello {
            supported_versions: vec![Version::new(2, 0, 0), Version::new(1, 5, 0)],
            max_frame_size: 1024,
            capabilities: vec![FrameCapabilities::from_str("pipelining").unwrap()],
            healthcheck: Some(true),
            engine_id: Some("engine-123".to_string()),
        };

        let frame = HaproxyHelloFrame {
            metadata: Metadata::default(),
            payload,
        };

        assert_eq!(frame.frame_type(), &FrameType::HaproxyHello);
        assert_eq!(frame.metadata().stream_id, 0);
        assert_eq!(frame.metadata().frame_id, 0);
        assert!(!frame.metadata().flags.is_fin());
        assert_eq!(
            frame.payload.supported_versions,
            vec![Version::new(2, 0, 0), Version::new(1, 5, 0)]
        );
        assert_eq!(frame.payload.max_frame_size, 1024);
        assert_eq!(
            frame.payload.capabilities,
            vec![FrameCapabilities::from_str("pipelining").unwrap()]
        );
        assert_eq!(frame.payload.healthcheck, Some(true));
        assert_eq!(frame.payload.engine_id, Some("engine-123".to_string()));

        let boxed: Box<HaproxyHelloFrame> = frame.into();
        assert_eq!(boxed.type_id(), TypeId::of::<Box<HaproxyHelloFrame>>());
    }

    #[test]
    fn test_haproxy_hello_frame_conversion() {
        let kv_list = HashMap::from([
            (
                "supported-versions".to_string(),
                TypedData::String("2.0, 1.5".to_string()),
            ),
            ("max-frame-size".to_string(), TypedData::UInt32(1024)),
            (
                "capabilities".to_string(),
                TypedData::String("pipelining".to_string()),
            ),
            ("healthcheck".to_string(), TypedData::Bool(true)),
            (
                "engine-id".to_string(),
                TypedData::String("engine-123".to_string()),
            ),
        ]);

        let payload = FramePayload::KVList(kv_list);
        let haproxy_hello: HaproxyHello = payload.try_into().unwrap();

        assert_eq!(
            haproxy_hello.supported_versions,
            vec![Version::new(2, 0, 0), Version::new(1, 5, 0)]
        );
        assert_eq!(haproxy_hello.max_frame_size, 1024);
        assert_eq!(
            haproxy_hello.capabilities,
            vec![FrameCapabilities::from_str("pipelining").unwrap()]
        );
        assert_eq!(haproxy_hello.healthcheck, Some(true));
        assert_eq!(haproxy_hello.engine_id, Some("engine-123".to_string()));
    }
}
