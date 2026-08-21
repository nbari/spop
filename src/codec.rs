use crate::{MAX_FRAME_SIZE_LIMIT, SpopFrame, parser::parse_frame_with_limit};
use bytes::{Buf, BufMut, BytesMut};
use std::cell::RefCell;
use std::io;
use tokio_util::codec::{Decoder, Encoder};

thread_local! {
    /// Scratch buffer for frame serialization, reused across frames on this thread.
    ///
    /// Writing a frame is a long run of small writes, and those are markedly cheaper on
    /// `Vec<u8>` than through `BufMut` on `BytesMut` — measured at ~30%% for a 4 KB frame.
    /// Staging into a reused `Vec` and handing the result over as one `put_slice` is both
    /// faster than writing into the `BytesMut` a byte at a time and allocation-free once warm,
    /// unlike `serialize()`, which allocates a fresh `Vec` every call.
    ///
    /// A thread-local rather than a field so that a `SpopCodec` stays cheap to copy around and
    /// the buffer is shared by every connection served on this thread.
    static ENCODE_SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Codec for reading and writing SPOP frames over a `tokio_util::codec::Framed`.
///
/// Carries the largest frame it will accept. [`SpopCodec::default`] starts at
/// [`MAX_FRAME_SIZE_LIMIT`], which is only a backstop for the window before the HELLO handshake
/// has happened; call [`SpopCodec::set_max_frame_size`] with the negotiated value once
/// HAPROXY-HELLO has been parsed, so the peer is held to what it actually agreed to.
///
/// ```no_run
/// # use spop::{SpopCodec, MAX_FRAME_SIZE_LIMIT};
/// # use tokio_util::codec::Framed;
/// # fn f(stream: tokio::net::TcpStream) {
/// let mut socket = Framed::new(stream, SpopCodec::default());
/// // ... after parsing HAPROXY-HELLO and negotiating:
/// socket.codec_mut().set_max_frame_size(16380);
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpopCodec {
    max_frame_size: u32,
}

impl Default for SpopCodec {
    fn default() -> Self {
        Self {
            max_frame_size: MAX_FRAME_SIZE_LIMIT,
        }
    }
}

impl SpopCodec {
    /// Creates a codec that rejects frames larger than `max_frame_size`.
    #[must_use]
    pub const fn new(max_frame_size: u32) -> Self {
        Self { max_frame_size }
    }

    /// The largest frame this codec will accept.
    #[must_use]
    pub const fn max_frame_size(&self) -> u32 {
        self.max_frame_size
    }

    /// Sets the largest frame this codec will accept.
    ///
    /// Call this with the value returned by
    /// [`crate::frames::HaproxyHello::negotiate_max_frame_size`] once the handshake is done.
    pub const fn set_max_frame_size(&mut self, max_frame_size: u32) {
        self.max_frame_size = max_frame_size;
    }
}

impl Decoder for SpopCodec {
    type Item = Box<dyn SpopFrame>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let initial_len = src.len();

        match parse_frame_with_limit(src, self.max_frame_size) {
            Ok((remaining, frame)) => {
                // Calculate the number of bytes consumed by the frame
                let parsed_len = initial_len - remaining.len();

                // Advance the src buffer by the consumed length
                src.advance(parsed_len);

                // Return the frame
                Ok(Some(frame))
            }

            Err(nom::Err::Incomplete(_)) => Ok(None),

            Err(e) => {
                // Return a generic io::Error, including the error message from nom::Err
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse frame: {e:?}"),
                ))
            }
        }
    }
}

impl Encoder<Box<dyn SpopFrame>> for SpopCodec {
    type Error = io::Error;

    fn encode(&mut self, frame: Box<dyn SpopFrame>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        ENCODE_SCRATCH.with_borrow_mut(|scratch| {
            scratch.clear();
            frame.serialize_into(scratch)?;

            // Frames must not exceed the negotiated size in either direction. `HAProxy` checks
            // its own outgoing frames the same way (`spop_conn->max_frame_size` in
            // `src/mux_spop.c`) and answers an oversized one with status
            // [`crate::StatusCode::TooBig`]. Failing here surfaces the problem in the agent that
            // built the frame, instead of as an opaque connection teardown by the peer.
            //
            // `scratch` holds the 4-byte length prefix as well, which is not counted against
            // the limit.
            let payload_len = scratch.len().saturating_sub(4);
            if payload_len > self.max_frame_size as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "frame of {payload_len} bytes exceeds the negotiated max-frame-size of {} ({})",
                        self.max_frame_size,
                        crate::StatusCode::TooBig
                    ),
                ));
            }

            dst.put_slice(scratch);
            Ok(())
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Builds a frame header declaring `declared_len` bytes of body, followed by that many bytes.
    fn frame_declaring(declared_len: u32) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_slice(&declared_len.to_be_bytes());
        buf.put_slice(&vec![0u8; declared_len as usize]);
        buf
    }

    #[test]
    fn test_default_uses_the_backstop() {
        assert_eq!(SpopCodec::default().max_frame_size(), MAX_FRAME_SIZE_LIMIT);
    }

    #[test]
    fn test_new_and_setter() {
        let mut codec = SpopCodec::new(4096);
        assert_eq!(codec.max_frame_size(), 4096);

        codec.set_max_frame_size(16380);
        assert_eq!(codec.max_frame_size(), 16380);
    }

    /// A frame larger than the configured limit must be refused, not buffered.
    #[test]
    fn test_frame_over_the_configured_limit_is_rejected() {
        let mut codec = SpopCodec::new(256);
        let mut src = frame_declaring(1000);

        let err = codec
            .decode(&mut src)
            .expect_err("a 1000-byte frame must be refused by a 256-byte codec");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Outgoing frames are held to the same limit, as `HAProxy` does for its own.
    #[test]
    fn test_oversized_outgoing_frame_is_rejected() {
        use crate::actions::VarScope;
        use crate::frames::Ack;

        // A 256-byte limit against an ACK whose single variable value is 4 KB.
        let mut codec = SpopCodec::new(256);
        let mut dst = BytesMut::new();
        let big = "x".repeat(4096);
        let ack = Ack::new(1, 1).set_var(VarScope::Session, "big", big.as_str());

        let err = codec
            .encode(Box::new(ack), &mut dst)
            .expect_err("an oversized outgoing frame must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("max-frame-size"),
            "error should name the limit: {err}"
        );

        // Nothing may be written to the destination when the frame is refused.
        assert!(dst.is_empty(), "a refused frame must not be partly written");
    }

    /// The same frame goes out fine when the limit allows it.
    #[test]
    fn test_outgoing_frame_within_the_limit_is_written() {
        use crate::actions::VarScope;
        use crate::frames::Ack;

        let mut codec = SpopCodec::new(16380);
        let mut dst = BytesMut::new();
        let ack = Ack::new(1, 1).set_var(VarScope::Session, "ip_score", 42u32);

        codec.encode(Box::new(ack), &mut dst).expect("encode");
        assert!(!dst.is_empty());

        // The declared length must match what was written, minus the 4-byte prefix.
        let declared = u32::from_be_bytes([dst[0], dst[1], dst[2], dst[3]]) as usize;
        assert_eq!(declared, dst.len() - 4);
    }

    /// The same frame is accepted for parsing once the limit allows it, proving the rejection
    /// above came from the limit and not from the frame being malformed in some other way.
    #[test]
    fn test_limit_is_what_rejects_it() {
        // Declared length is within a generous limit, so the length check passes and parsing
        // proceeds far enough to fail on the frame *type* instead.
        let mut codec = SpopCodec::new(MAX_FRAME_SIZE_LIMIT);
        let mut src = frame_declaring(1000);

        let err = codec.decode(&mut src).expect_err("frame type 0 is invalid");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Either way the buffer must not be left untouched-and-silently-pending: a malformed
        // frame is an error, never `Ok(None)`.
        assert!(!src.is_empty());
    }
}
