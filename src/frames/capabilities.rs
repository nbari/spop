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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameCapabilities {
    Pipelining,
}

impl FromStr for FrameCapabilities {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("pipelining") {
            // Add more capabilities as needed
            Ok(Self::Pipelining)
        } else {
            Err(format!("Unknown capability: {s}"))
        }
    }
}

impl FrameCapabilities {
    /// The wire name of this capability.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            // Add more capabilities here when needed
            Self::Pipelining => "pipelining",
        }
    }
}

impl fmt::Display for FrameCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
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
