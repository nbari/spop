use std::{fmt, str::FromStr};

/// Frame capabilities
///
/// <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L736>
///
/// ```text
/// 3.2.1. Frame capabilities
/// --------------------------
///
/// Here are the list of official capabilities that HAProxy and agents can support:
///
///   * pipelining: This is the ability for a peer to decouple NOTIFY and ACK
///                 frames. This is a symmectical capability. To be used, it must
///                 be supported by HAProxy and agents. Unlike HTTP pipelining, the
///                 ACK frames can be send in any order, but always on the same TCP
///                 connection used for the corresponding NOTIFY frame.
///
/// Unsupported or unknown capabilities are silently ignored, when possible.
///
/// NOTE: Fragmentation and async capabilities were deprecated and are now ignored.
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameCapabilities {
    Pipelining,
}

impl FromStr for FrameCapabilities {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pipelining" => Ok(Self::Pipelining),
            // Add more capabilities as needed
            _ => Err(format!("Unknown capability: {s}")),
        }
    }
}

impl fmt::Display for FrameCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Pipelining => "pipelining",
            // Add more capabilities here when needed
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_capabilities() {
        assert_eq!(
            FrameCapabilities::from_str("pipelining").unwrap(),
            FrameCapabilities::Pipelining
        );
        assert_eq!(FrameCapabilities::Pipelining.to_string(), "pipelining");
        assert!(FrameCapabilities::from_str("unknown").is_err());
    }
}
