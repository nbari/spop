//! SPOP error status codes.
//!
//! <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L1102>
//!
//! ```text
//! 3.5. Errors & timeouts
//! ----------------------
//!
//! Here is the list of all known errors:
//!
//!     STATUS CODE   |  DESCRIPTION
//!   ----------------+--------------------------------------------------------
//!      0            | normal (no error occurred)
//!      1            | I/O error
//!      2            | A timeout occurred
//!      3            | frame is too big
//!      4            | invalid frame received
//!      5            | version value not found
//!      6            | max-frame-size value not found
//!      7            | capabilities value not found
//!      8            | unsupported version
//!      9            | max-frame-size too big or too small
//!      10           | payload fragmentation is not supported
//!      11           | invalid interlaced frames
//!      12           | frame-id not found (it does not match any referenced frame)
//!      13           | resource allocation error
//!      99           | an unknown error occurrde
//!   ----------------+--------------------------------------------------------
//!
//! An agent can define its own errors using a not yet assigned status code.
//! ```
//!
//! Because agents may define their own codes, [`StatusCode::from_u32`] never fails: an
//! unassigned value round-trips through [`StatusCode::Other`].

/// A SPOP status code, as carried by the `status-code` item of HAPROXY-DISCONNECT and
/// AGENT-DISCONNECT frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    /// normal (no error occurred)
    None,
    /// I/O error
    Io,
    /// A timeout occurred
    Timeout,
    /// frame is too big
    TooBig,
    /// invalid frame received
    Invalid,
    /// version value not found
    NoVersion,
    /// max-frame-size value not found
    NoFrameSize,
    /// capabilities value not found
    NoCapabilities,
    /// unsupported version
    BadVersion,
    /// max-frame-size too big or too small
    BadFrameSize,
    /// payload fragmentation is not supported
    FragmentationNotSupported,
    /// invalid interlaced frames
    InterlacedFrames,
    /// frame-id not found (it does not match any referenced frame)
    FrameIdNotFound,
    /// resource allocation error
    Resource,
    /// an unknown error occurred
    Unknown,
    /// An agent-defined code, using a value not assigned by the specification.
    Other(u32),
}

impl StatusCode {
    /// Converts a raw wire value into a `StatusCode`.
    ///
    /// Values the specification does not assign become [`StatusCode::Other`] rather than an
    /// error, because the specification explicitly allows agents to define their own codes.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Io,
            2 => Self::Timeout,
            3 => Self::TooBig,
            4 => Self::Invalid,
            5 => Self::NoVersion,
            6 => Self::NoFrameSize,
            7 => Self::NoCapabilities,
            8 => Self::BadVersion,
            9 => Self::BadFrameSize,
            10 => Self::FragmentationNotSupported,
            11 => Self::InterlacedFrames,
            12 => Self::FrameIdNotFound,
            13 => Self::Resource,
            99 => Self::Unknown,
            other => Self::Other(other),
        }
    }

    /// Converts the `StatusCode` to its wire value.
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Io => 1,
            Self::Timeout => 2,
            Self::TooBig => 3,
            Self::Invalid => 4,
            Self::NoVersion => 5,
            Self::NoFrameSize => 6,
            Self::NoCapabilities => 7,
            Self::BadVersion => 8,
            Self::BadFrameSize => 9,
            Self::FragmentationNotSupported => 10,
            Self::InterlacedFrames => 11,
            Self::FrameIdNotFound => 12,
            Self::Resource => 13,
            Self::Unknown => 99,
            Self::Other(other) => other,
        }
    }

    /// The reason string `HAProxy` uses for this code.
    ///
    /// Matches `spop_err_reasons` in `HAProxy`'s `src/mux_spop.c`, so a DISCONNECT frame built
    /// from a `StatusCode` reports the same text `HAProxy` would.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::None => "normal",
            Self::Io => "I/O error",
            Self::Timeout => "a timeout occurred",
            Self::TooBig => "frame is too big",
            Self::Invalid => "invalid frame received",
            Self::NoVersion => "version value not found",
            Self::NoFrameSize => "max-frame-size value not found",
            Self::NoCapabilities => "capabilities value not found",
            Self::BadVersion => "unsupported version",
            Self::BadFrameSize => "max-frame-size too big or too small",
            Self::FragmentationNotSupported => "fragmentation not supported",
            Self::InterlacedFrames => "invalid interlaced frames",
            Self::FrameIdNotFound => "frame-id not found",
            Self::Resource => "resource allocation error",
            Self::Unknown | Self::Other(_) => "an unknown error occurred",
        }
    }
}

impl From<u32> for StatusCode {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<StatusCode> for u32 {
    fn from(value: StatusCode) -> Self {
        value.to_u32()
    }
}

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message(), self.to_u32())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_all_assigned_codes() {
        for code in (0..=13).chain(std::iter::once(99)) {
            assert_eq!(StatusCode::from_u32(code).to_u32(), code);
        }
    }

    #[test]
    fn test_agent_defined_codes_round_trip() {
        // The spec allows agents to define their own codes using unassigned values.
        assert_eq!(StatusCode::from_u32(42), StatusCode::Other(42));
        assert_eq!(StatusCode::Other(42).to_u32(), 42);
        assert_eq!(StatusCode::from_u32(100).to_u32(), 100);
    }

    #[test]
    fn test_messages_match_haproxy() {
        assert_eq!(StatusCode::None.message(), "normal");
        assert_eq!(StatusCode::BadVersion.message(), "unsupported version");
        assert_eq!(
            StatusCode::BadFrameSize.message(),
            "max-frame-size too big or too small"
        );
        assert_eq!(StatusCode::Other(42).message(), "an unknown error occurred");
    }

    #[test]
    fn test_display() {
        assert_eq!(StatusCode::Timeout.to_string(), "a timeout occurred (2)");
    }
}
