use crate::{SpopFrame, parser::parse_frame};
use bytes::{Buf, BufMut, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

pub struct SpopCodec;

impl Decoder for SpopCodec {
    type Item = Box<dyn SpopFrame>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let initial_len = src.len();

        match parse_frame(src) {
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
        let serialized = frame.serialize()?;

        dst.put_slice(&serialized);

        Ok(())
    }
}
