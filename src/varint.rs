use nom::{
    IResult,
    error::{Error, ErrorKind},
    number::complete::be_u8,
};

/// <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L659-L667>
///
/// ```text
/// Variable-length integer (varint) are encoded using Peers encoding:
///
///
///        0  <= X < 240        : 1 byte  (7.875 bits)  [ XXXX XXXX ]
///       240 <= X < 2288       : 2 bytes (11 bits)     [ 1111 XXXX ] [ 0XXX XXXX ]
///      2288 <= X < 264432     : 3 bytes (18 bits)     [ 1111 XXXX ] [ 1XXX XXXX ]   [ 0XXX XXXX ]
///    264432 <= X < 33818864   : 4 bytes (25 bits)     [ 1111 XXXX ] [ 1XXX XXXX ]*2 [ 0XXX XXXX ]
///  33818864 <= X < 4328786160 : 5 bytes (32 bits)     [ 1111 XXXX ] [ 1XXX XXXX ]*3 [ 0XXX XXXX ]
///  ...
///
/// ```
#[must_use]
pub const fn varint_len(i: u64) -> usize {
    if i < 240 {
        1
    } else {
        let mut len = 2;
        let mut value = (i - 240) >> 4;

        while value >= 128 {
            len += 1;
            value = (value - 128) >> 7;
        }

        len
    }
}

/// Encodes a varint by appending it to `buf`.
///
/// Allocation-free: the caller owns the buffer. Pair it with [`varint_len`] when you need to
/// size that buffer up front.
#[allow(clippy::cast_possible_truncation)]
pub fn encode_varint_into(i: u64, buf: &mut Vec<u8>) {
    if i < 240 {
        buf.push(i as u8);
    } else {
        buf.push((i | 0b1111_0000) as u8);
        let mut i = (i - 240) >> 4;

        while i >= 128 {
            buf.push((i | 0b1000_0000) as u8);
            i = (i - 128) >> 7;
        }

        buf.push(i as u8);
    }
}

/// Decodes a variable-length integer (varint) from the input byte slice.
///
/// # Errors
///
/// Returns an error if the input is incomplete or malformed.
pub fn decode_varint(input: &[u8]) -> IResult<&[u8], u64> {
    let (mut input, first_byte) = be_u8(input)?;

    if first_byte < 240 {
        return Ok((input, u64::from(first_byte)));
    }

    let mut value = u64::from(first_byte);
    let mut shift = 4u32;

    loop {
        let (new_input, next_byte) = be_u8(input)?;
        input = new_input;

        // The first byte carries 4 payload bits and each continuation byte carries 7, so a u64
        // needs at most 10 bytes. Without this bound `shift` runs past 63 and both the shift and
        // the addition overflow on attacker-controlled input: a panic in debug builds, a silently
        // wrong value in release.
        //
        // `checked_shl` guards the shift amount, not bits shifted off the top, so a non-minimal
        // encoding can still decode to a value that is wrong rather than rejected. That matches
        // `HAProxy`'s own decoder, which performs no canonical-form check either, and it cannot
        // reach past this function: string and binary lengths are bounds-checked against the
        // remaining input by the caller, so an inflated length errors rather than over-reading.
        let addend = u64::from(next_byte)
            .checked_shl(shift)
            .ok_or_else(|| nom::Err::Error(Error::new(input, ErrorKind::TooLarge)))?;

        value = value
            .checked_add(addend)
            .ok_or_else(|| nom::Err::Error(Error::new(input, ErrorKind::TooLarge)))?;

        shift += 7;

        if next_byte < 128 {
            break;
        }
    }

    Ok((input, value))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::unreadable_literal)]
mod tests {
    use super::*;

    /// `shift` used to climb past 63 with no cap on continuation bytes, overflowing both the
    /// shift and the addition: a panic in debug builds, a silently wrong value in release. This
    /// input is reachable from the very first varint of every frame (the stream-id).
    #[test]
    fn test_decode_varint_rejects_overlong_input() {
        let mut input = vec![0xF0];
        input.extend(std::iter::repeat_n(0x80, 12));
        input.push(0x01);

        assert!(
            decode_varint(&input).is_err(),
            "an overlong varint must be rejected, not overflow"
        );
    }

    /// A u64 needs at most 10 bytes (4 payload bits in the first, 7 in each continuation), so
    /// the widest legitimate value must still decode.
    #[test]
    fn test_decode_varint_accepts_widest_legitimate_value() {
        let mut encoded = Vec::new();
        encode_varint_into(u64::MAX, &mut encoded);

        assert!(encoded.len() <= 10, "u64::MAX must fit in 10 bytes");

        let (rest, decoded) = decode_varint(&encoded).expect("u64::MAX must round-trip");
        assert_eq!(decoded, u64::MAX);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_decode_varint() {
        assert_eq!(decode_varint(&[0x00]), Ok((&[][..], 0)));

        assert_eq!(decode_varint(&[0x01]), Ok((&[][..], 1)));

        assert_eq!(decode_varint(&[0x0F]), Ok((&[][..], 15)));

        assert_eq!(decode_varint(&[0xEF, 0x01]), Ok((&[0x01][..], 239)));

        assert_eq!(decode_varint(&[0xF0, 0x00]), Ok((&[][..], 240)));

        assert_eq!(decode_varint(&[0xF1, 0x00]), Ok((&[][..], 241)));

        assert_eq!(decode_varint(&[0xFC, 0x03]), Ok((&[][..], 300)));

        assert_eq!(decode_varint(&[0xFF, 0x7F]), Ok((&[][..], 2287)));

        assert_eq!(decode_varint(&[0xF0, 0x80, 0x00]), Ok((&[][..], 2288)));

        assert_eq!(decode_varint(&[0xF4, 0x88, 0x00]), Ok((&[][..], 2420)));

        assert_eq!(
            decode_varint(&[0xF0, 0x80, 0x80, 0x0]),
            Ok((&[][..], 264432))
        );

        assert_eq!(
            decode_varint(&[0xF0, 0x80, 0x80, 0x80, 0x0]),
            Ok((&[][..], 33818864))
        );
    }

    #[test]
    fn test_varint_1_byte() {
        // 1-byte encoding: 0 <= X < 240
        let data = [0x10]; // 16 in decimal
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 16);

        let data = [0xEF]; // 239 in decimal (max 1-byte)
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 239);

        assert_eq!(decode_varint(&[239]), Ok((&[][..], 239))); // 1 byte test.
    }

    #[test]
    fn test_varint_2_bytes() {
        // 2-byte encoding: 240 <= X < 2288
        let data = [0xF0, 0x00]; // 240
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 240);

        let data = [0xF1, 0x00]; // 241
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 241);

        let data = [0xFC, 0x03]; // 243
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 300);

        let data = [0xFF, 0x7F]; // 2287 (max 2-byte)
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 2287);

        assert_eq!(decode_varint(&[250, 0]), Ok((&[][..], 250))); // 2 bytes test.
        assert_eq!(decode_varint(&[255, 127]), Ok((&[][..], 2287))); // 2 bytes test.
    }

    #[test]
    fn test_varint_3_bytes() {
        // 3-byte encoding: 2288 <= X < 264432
        assert_eq!(decode_varint(&[240, 128, 0]), Ok((&[][..], 2288)));

        let data = [0xF0, 0x80, 0x00]; // 2288
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 2288);

        let data = [0xF4, 0x88, 0x00]; // 2420
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 2420);

        let data = [0xFF, 0xFF, 0x7F]; // 264431 (max 3-byte)
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 264431);

        assert_eq!(decode_varint(&[244, 136, 0]), Ok((&[][..], 2420))); // 3 bytes test.
        assert_eq!(decode_varint(&[255, 0xFF, 0x7F]), Ok((&[][..], 264431))); // 3 bytes test.
    }

    #[test]
    fn test_varint_4_bytes() {
        // 4-byte encoding: 264432 <= X < 33818864
        let data = [0xF0, 0x80, 0x80, 0x00]; // 264432
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 264432);

        let data = [0xF0, 0xF4, 0xFE, 0x04]; // Random middle value
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 1572912);

        let data = [0xFF, 0xFF, 0xFF, 0x7F]; // 33818863 (max 4-byte)
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 33818863);
    }

    #[test]
    fn test_varint_5_bytes() {
        // 5-byte encoding: 33818864 <= X < 4328786160
        let data = [0xF0, 0x80, 0x80, 0x80, 0x00]; // 33818864
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 33818864);

        let data = [0xF0, 0xDC, 0xAC, 0xB0, 0x07]; // Random middle value
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 281374384);

        let data = [0xFF, 0xFF, 0xFF, 0xFF, 0x7F]; // 4328786159 (max 5-byte)
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 4328786159);
    }

    #[test]
    fn test_varint_6_bytes() {
        // 6-byte encoding: 4328786160 <= X
        let data = [0xF0, 0x80, 0x80, 0x80, 0x80, 0x00]; // 4328786160
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 4328786160);

        let data = [0xF1, 0x80, 0x80, 0x80, 0x80, 0x00]; // 4328786161
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 4328786161);

        let data = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];
        let (_, value) = decode_varint(&data).expect("Failed to decode varint");
        assert_eq!(value, 554084600047);
    }

    #[test]
    fn test_encode_decode_varint() {
        // Test cases to cover all different byte ranges
        let test_values: Vec<u64> = vec![
            0,           // 1 byte
            239,         // 1 byte
            240,         // 2 bytes
            2287,        // 2 bytes
            2288,        // 3 bytes
            264432,      // 4 bytes
            4328786160,  // 5 bytes
            10000000000, // Large value
        ];

        for &value in &test_values {
            // Encode the value
            let mut encoded = Vec::new();
            encode_varint_into(value, &mut encoded);

            // Decode the encoded value
            let (remaining_input, decoded) =
                decode_varint(&encoded).expect("Failed to decode varint");

            // Assert that the decoded value matches the original
            assert_eq!(value, decoded);

            // Ensure there is no extra data left after decoding
            assert!(
                remaining_input.is_empty(),
                "Remaining input should be empty"
            );
        }
    }

    #[test]
    fn test_encode_decode_varint_loop() {
        // Test encoding and decoding a large number of values
        for i in 0..300000 {
            let mut encoded = Vec::new();
            encode_varint_into(i, &mut encoded);
            let (remaining_input, decoded) =
                decode_varint(&encoded).expect("Failed to decode varint");
            assert_eq!(i, decoded, "Failed for value: {i}");
            assert!(remaining_input.is_empty());
        }
    }
}
