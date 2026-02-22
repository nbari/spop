use crate::{
    SpopFrame,
    frame::{FrameFlags, FramePayload, FrameType, Message, Metadata},
    frames::haproxy_disconnect::{HaproxyDisconnect, HaproxyDisconnectFrame},
    frames::haproxy_hello::{HaproxyHello, HaproxyHelloFrame},
    frames::notify::NotifyFrame,
    types::{TypedData, typed_data},
    varint::decode_varint,
};
use nom::{
    Err, IResult, Parser,
    bytes::complete::take,
    combinator::{all_consuming, complete},
    error::{Error, ErrorKind},
    multi::{many_m_n, many0},
    number::streaming::{be_u8, be_u32},
};
use std::collections::HashMap;

/// Parse a frame from the input byte slice
///
/// # Errors
///
/// Returns an error if the input is incomplete, malformed, or contains an unsupported frame type.
#[allow(clippy::cast_possible_truncation, clippy::indexing_slicing)]
pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Box<dyn SpopFrame>> {
    // Exchange between HAProxy and agents are made using FRAME packets. All frames must be
    // prefixed with their size encoded on 4 bytes in network byte order:
    // <FRAME-LENGTH:4 bytes> <FRAME>
    //
    let (input, frame_length) = be_u32(input)?;
    // Check if the input has enough bytes for the frame
    // If not, return the same error nom would return.
    if input.len() < frame_length as usize {
        return Err(nom::Err::Incomplete(nom::Needed::new(
            frame_length as usize - input.len(),
        )));
    }

    // Extract only frame body
    let (remaining, frame) = take(frame_length)(input)?;

    // check if the frame length is correct
    if frame.len() != frame_length as usize {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    //A frame always starts with its type, on one byte, followed by metadata containing flags, on 4
    //bytes and a two variable-length integer representing the stream identifier and the frame
    //identifier inside the stream:
    //
    // FRAME       : <FRAME-TYPE:1 byte> <METADATA> <FRAME-PAYLOAD>
    let (frame, frame_type_byte) = be_u8(frame)?; // Read 1-byte frame type

    // Convert the byte to a FrameType
    let frame_type = FrameType::from_u8(frame_type_byte)
        .map_err(|_| Err::Error(Error::new(input, ErrorKind::Alt)))?;

    // METADATA    : <FLAGS:4 bytes> <STREAM-ID:varint> <FRAME-ID:varint>
    let (frame, flags_value) = be_u32(frame)?; // Read 4-byte flags

    // Convert the flags to a FrameFlags
    let flags = FrameFlags::from_u32(flags_value)
        .map_err(|_| Err::Error(Error::new(input, ErrorKind::Alt)))?;

    if flags.is_abort() {
        return Err(nom::Err::Failure(Error::new(input, ErrorKind::Verify)));
    }

    let (frame, stream_id) = decode_varint(frame)?;
    let (frame, frame_id) = decode_varint(frame)?;

    // Create the metadata structure
    let metadata = Metadata {
        flags,
        stream_id,
        frame_id,
    };

    // Then comes the frame payload. Depending on the frame type, the payload can be
    // of three types: a simple key/value list, a list of messages or a list of
    // actions.
    //
    //     FRAME-PAYLOAD    : <LIST-OF-MESSAGES> | <LIST-OF-ACTIONS> | <KV-LIST>
    //
    //     LIST-OF-MESSAGES : [ <MESSAGE-NAME> <NB-ARGS:1 byte> <KV-LIST> ... ]
    //     MESSAGE-NAME     : <STRING>
    //
    //     LIST-OF-ACTIONS  : [ <ACTION-TYPE:1 byte> <NB-ARGS:1 byte> <ACTION-ARGS> ... ]
    //     ACTION-ARGS      : [ <TYPED-DATA>... ]
    //
    //     KV-LIST          : [ <KV-NAME> <KV-VALUE> ... ]
    //     KV-NAME          : <STRING>
    //     KV-VALUE         : <TYPED-DATA>
    //
    let frame_payload = frame;

    match frame_type {
        // 3.2.4. Frame: HAPROXY-HELLO
        // This frame is the first one exchanged between HAProxy and an agent, when the connection
        // is established.
        //
        // The payload of this frame is a KV-LIST. STREAM-ID and FRAME-ID are must be set 0.
        FrameType::HaproxyHello => {
            let mut parser = all_consuming(parse_key_value_pairs);

            let (_, payload) = parser.parse(frame_payload)?;

            // check mandatory items
            let hello = HaproxyHello::try_from(payload)
                .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::Tag)))?;

            let frame = HaproxyHelloFrame {
                metadata,
                payload: hello,
            };

            Ok((remaining, Box::new(frame)))
        }

        // 3.2.8. Frame: HAPROXY-DISCONNECT
        // If an error occurs, at anytime, from the HAProxy side, a HAPROXY-DISCONNECT frame is
        // sent with information describing the error. HAProxy will wait an AGENT-DISCONNECT frame
        // in reply. All other frames will be ignored. The agent must then close the socket.
        //
        // The payload of this frame is a KV-LIST. STREAM-ID and FRAME-ID are must be set 0.
        FrameType::HaproxyDisconnect => {
            let mut parser = all_consuming(parse_key_value_pairs);

            let (_, payload) = parser.parse(frame_payload)?;

            // check mandatory items
            let disconnect = HaproxyDisconnect::try_from(payload)
                .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::Tag)))?;

            let frame = HaproxyDisconnectFrame {
                metadata,
                payload: disconnect,
            };

            Ok((remaining, Box::new(frame)))
        }

        // 3.2.6. Frame: NOTIFY
        // Information are sent to the agents inside NOTIFY frames. These frames are attached to a
        // stream, so STREAM-ID and FRAME-ID must be set.
        //
        // The payload of NOTIFY frames is a LIST-OF-MESSAGES.
        FrameType::Notify => {
            let mut parser = all_consuming(parse_list_of_messages);

            let (_, messages) = parser.parse(frame_payload)?;

            let frame = NotifyFrame { metadata, messages };

            Ok((remaining, Box::new(frame)))
        }

        // Unknown frames may be silently skipped or trigger an error, depending on the
        // implementation.
        _ => Err(nom::Err::Failure(Error::new(input, ErrorKind::NoneOf))),
    }
}

/// Parse entire KV-LIST payload
fn parse_key_value_pairs(input: &[u8]) -> IResult<&[u8], FramePayload> {
    // Create the parser combinator chain
    let mut parser = all_consuming(many0(complete(parse_key_value_pair)));

    // Execute the parser with the input
    let (input, pairs) = parser.parse(input)?;

    let mut map = HashMap::new();

    // handle duplicate keys
    for (key, value) in pairs {
        if map.contains_key(&key) {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::Tag)));
        }
        map.insert(key, value);
    }

    Ok((input, FramePayload::KVList(map)))
}

/// Parse a key-value pair (used in KV-LIST)
/// A KV-LIST is a list of key/value pairs. Each pair is made of:
/// - a name (STRING)
/// - a value (TYPED-DATA)
fn parse_key_value_pair(input: &[u8]) -> IResult<&[u8], (String, TypedData)> {
    // KV-NAME is a <STRING> (varint length + bytes)
    let (input, key) = parse_string(input)?;

    // Ensure we have at least 1 byte left for the type
    if input.is_empty() {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    // KV-VALUE is a <TYPED-DATA>
    let (input, value) = typed_data(input)?;

    Ok((input, (key, value)))
}

/// Parse a length-prefixed string
fn parse_string(input: &[u8]) -> IResult<&[u8], String> {
    let (input, length) = decode_varint(input)?;
    let length: usize = length
        .try_into()
        .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::TooLarge)))?;

    if input.len() < length {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    let (input, bytes) = take(length)(input)?;

    String::from_utf8(bytes.to_vec())
        .map(|s| (input, s))
        .map_err(|_| nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)))
}

/// Parse entire list of messages payload
///
/// LIST-OF-MESSAGES : [ <MESSAGE-NAME> <NB-ARGS:1 byte> <KV-LIST> ... ]
/// MESSAGE-NAME     : <STRING>
#[allow(clippy::indexing_slicing)]
fn parse_list_of_messages(input: &[u8]) -> IResult<&[u8], Vec<Message>> {
    let mut remaining = input;
    let mut messages = vec![];

    while !remaining.is_empty() {
        let (local_remaining, message) = parse_string(remaining)?;

        let (local_remaining, nb_args_bytes) = take(1usize)(local_remaining)?;

        let nb_args = nb_args_bytes[0] as usize;

        let mut parser = many_m_n(nb_args, nb_args, parse_key_value_pair);
        let (local_remaining, kv_list) = parser.parse(local_remaining)?;
        remaining = local_remaining;

        let mut map = HashMap::new();

        // handle duplicate keys
        for (key, value) in kv_list {
            if map.contains_key(&key) {
                return Err(nom::Err::Failure(Error::new(input, ErrorKind::Tag)));
            }
            map.insert(key, value);
        }

        messages.push(Message {
            name: message,
            args: map,
        });
    }
    Ok((remaining, messages))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[rustfmt::skip]
    const HAPROXY_HELLO: &[u8] = &[
        0x00, 0x00, 0x00, 0x4e, // FRAME-LENGTH = 78 bytes
        0x01,                   // FRAME-TYPE = HAPROXY-HELLO
        0x00, 0x00, 0x00, 0x01, // FLAGS = FIN
        0x00,                   // STREAM-ID = 0
        0x00,                   // FRAME-ID = 0
        // FRAME-PAYLOAD
        0x12,
            // "supported-versions"
            0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65,
            0x64, 0x2d, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
            0x6e, 0x73,
        0x08, 0x03, // TYPE=STRING, len = 3
            0x32, 0x2e, 0x30, // 2.0
        0x0e,
            // "max-frame-size"
            0x6d, 0x61, 0x78, 0x2d, 0x66, 0x72, 0x61, 0x6d,
            0x65, 0x2d, 0x73, 0x69, 0x7a, 0x65,
        0x03, // TYPE=UINT32,
            0xfc, 0xf0, 0x06,
        0x0c,
            // "capabilities"
            0x63, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69,
            0x74, 0x69, 0x65, 0x73,
        0x08, 0x00, // TYPE=STRING, null
        0x0b,
            // "healthcheck"
            0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x63, 0x68,
            0x65, 0x63, 0x6b,
        0x11, // TYPE=BOOLEAN, true
    ];

    #[test]
    fn test_parse_haproxy_hello() {
        let (_, frame) = parse_frame(HAPROXY_HELLO).expect("Parses correctly");
        assert_eq!(frame.frame_type(), &FrameType::HaproxyHello);
        assert!(frame.metadata().flags.is_fin());
        assert!(!frame.metadata().flags.is_abort());
        assert_eq!(frame.metadata().stream_id, 0);
        assert_eq!(frame.metadata().frame_id, 0);

        match frame.payload() {
            FramePayload::KVList(kv_list) => {
                let data = kv_list
                    .get("supported-versions")
                    .expect("Has supported versions");
                assert_eq!(data, &TypedData::String("2.0".to_string()));

                let data = kv_list.get("max-frame-size").expect("Has max frame size");
                assert_eq!(data, &TypedData::UInt32(16380));

                let data = kv_list.get("capabilities").expect("Has capabilities");
                assert_eq!(data, &TypedData::String(String::new()));

                let data = kv_list.get("healthcheck").expect("Has healthcheck");
                assert_eq!(data, &TypedData::Bool(true));
            }
            _ => {
                panic!("Wrong type of payload");
            }
        }
    }

    #[test]
    fn test_parse_haproxy_disconnect() {
        let frame: &[u8] = &[
            0x00, 0x00, 0x00, 0x25, // FRAME-LENGTH = 37
            0x02, // FRAME-TYPE: HAPROXY-DISCONNECT
            0x00, 0x00, 0x00, 0x01, // FLAGS = FIN
            0x00, // STREAM-ID = 0
            0x00, // FRAME-ID = 0
            0x0b, // key: "status-code"
            0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2d, 0x63, 0x6f, 0x64, 0x65, 0x03,
            0x00, // TYPE-UINT32=0
            0x07, // key: "message"
            0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x08,
            0x06, // TYPE-STRING, len = 6, "normal"
            0x6e, 0x6f, 0x72, 0x6d, 0x61, 0x6c,
        ];
        match parse_frame(frame) {
            Ok((_, spop_message)) => {
                assert_eq!(*spop_message.frame_type(), FrameType::HaproxyDisconnect);
                match spop_message.payload() {
                    FramePayload::KVList(messages) => {
                        assert_eq!(messages.get("status-code"), Some(&TypedData::UInt32(0)));
                        assert_eq!(
                            messages.get("message"),
                            Some(&TypedData::String("normal".into()))
                        );
                    }
                    _ => {
                        panic!("Expected a KVList payload, but got a different type");
                    }
                }
            }
            Err(e) => {
                panic!(
                    "Expected a valid HaproxyDisconnect frame, but got an incomplete frame: {e:?}"
                );
            }
        }
    }

    #[test]
    fn test_incomplete_frame() {
        let frame: &[u8] = &[
            0x00, 0x00, 0x00, 0xd7, // FRAME-LENGTH = 215 bytes
            0x03, // FRAME-TYPE: NOTIFY
            0x00, 0x00, 0x00, 0x01, // FLAGS = FIN
            0x49, // STREAM-ID = 0x49/73
            0x01, // FRAME-ID = 1
            0x03, // message name: "tls"
            0x74, 0x6c, 0x73, 0x08, // NB-ARGS=8
            // ARG1
            0x11, // len = 17
            // "protocol_hello_id"
            0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x5f, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
            0x5f, 0x69, 0x64, 0x04, // TYPE=INT64,
            0xf3, 0x21, // ARG2
            0x0c, // len = 12
            // "http_version"
            0x68, 0x74, 0x74, 0x70, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
            // TYPE=STRING, len = 3
            // "2.0"
            0x08, 0x03, 0x32, 0x2e, 0x30, // ARG3
            0x12, // len = 18
            // "supported_versions"
            0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x73, // TYPE=BYTES, len = 4
            0x09, 0x04, 0x03, 0x04, 0x03, 0x03, // TLS 1.3 and 1.2
            // ARG4
            0x07, // len = 7
            // "has_sni"
            0x68, 0x61, 0x73, 0x5f, 0x73, 0x6e, 0x69, // TYPE=BOOLEAN, true
            0x11, // ARG5
            0x04, // len =4
            // "alpn"
            0x61, 0x6c, 0x70, 0x6e, 0x08, 0x02,
            // TYPE=STRING, len = 2
            // "h2"
            0x68, 0x32, // ARG6
            0x0a, // len = 10
            // "cipherlist"
            0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x6c, 0x69, 0x73, 0x74,
            // TYPE=BYTES, len = 38
            0x09, 0x26, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8,
            0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f,
            0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
            // ARG7
            0x07, // len = 7
            // "extlist"
            0x65, 0x78, 0x74, 0x6c, 0x69, 0x73, 0x74, // TYPE=BYTES, len = 22
            0x09, 0x16, 0x00, 0x00, 0x00, 0x0b, 0xff, 0x01, 0x00, 0x17, 0x00, 0x12, 0x00, 0x05,
            0x00, 0x0a, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x2b, 0x00, 0x33,
            // ARG8 is missing
        ];
        match parse_frame(frame) {
            Err(nom::Err::Incomplete(_)) => {
                // This is expected, as the frame is incomplete
            }
            _ => {
                panic!("Expected an incomplete frame error, but got a valid frame");
            }
        }
    }

    // Test that a NOTIFY frame with no messages is parsed correctly
    #[test]
    fn test_parse_notify_no_messages() {
        let frame: &[u8] = &[
            0x00, 0x00, 0x00, 0x07, // FRAME-LENGTH = 8 bytes
            0x03, // FRAME-TYPE: NOTIFY
            0x00, 0x00, 0x00, 0x01, // FLAGS = FIN
            0x01, // STREAM-ID = 1
            0x01, // FRAME-ID = 1
        ];
        let (_, spop_message) = parse_frame(frame).expect("Parses correctly");
        assert_eq!(*spop_message.frame_type(), FrameType::Notify);
        assert!(spop_message.metadata().flags.is_fin());
        assert!(!spop_message.metadata().flags.is_abort());
        assert_eq!(spop_message.metadata().stream_id, 1);
        assert_eq!(spop_message.metadata().frame_id, 1);
        match spop_message.payload() {
            FramePayload::ListOfMessages(messages) => {
                assert!(messages.is_empty(), "Expected an empty list of messages");
            }
            _ => {
                panic!("Expected a Messages payload, but got a different type");
            }
        }
    }

    // Test that a NOTIFY frame with two messages is parsed correctly
    #[test]
    fn test_parse_notify_two_messages() {
        let frame: &[u8] = &[
            0x00, 0x00, 0x00, 0x13, // FRAME-LENGTH = 19 bytes
            0x03, // FRAME-TYPE: NOTIFY
            0x00, 0x00, 0x00, 0x01, // FLAGS = FIN
            0x01, // STREAM-ID = 1
            0x01, // FRAME-ID = 1
            0x04, // message name: "msg1"
            0x6d, 0x73, 0x67, 0x31, // "msg1"
            0x00, // NB-ARGS = 0
            0x04, // message name: "msg2"
            0x6d, 0x73, 0x67, 0x32, // "msg2"
            0x00, // NB-ARGS = 0
        ];
        let (_, spop_message) = parse_frame(frame).expect("Parses correctly");
        assert_eq!(*spop_message.frame_type(), FrameType::Notify);
        assert!(spop_message.metadata().flags.is_fin());
        assert!(!spop_message.metadata().flags.is_abort());
        assert_eq!(spop_message.metadata().stream_id, 1);
        assert_eq!(spop_message.metadata().frame_id, 1);
        match spop_message.payload() {
            FramePayload::ListOfMessages(messages) => {
                assert_eq!(messages.len(), 2, "Expected two messages");
            }
            _ => {
                panic!("Expected a Messages payload, but got a different type");
            }
        }
    }

    // Test that a NOTIFY frame with a message that is too short fails to parse.
    #[test]
    fn test_parse_notify_msg_too_short() {
        let frame: &[u8] = &[
            0x00, 0x00, 0x00, 0x1C, // FRAME-LENGTH = 28 bytes
            0x03, // FRAME-TYPE: NOTIFY
            0x00, 0x00, 0x00, 0x01, // FLAGS = FIN
            0x01, // STREAM-ID = 1
            0x01, // FRAME-ID = 1
            0x04, // message name: "msg1"
            0x6d, 0x73, 0x67, 0x31, // "msg1"
            0x00, // NB-ARGS = 0
            0x04, // message name: "msg2"
            0x6d, 0x73, 0x67, 0x32, // "msg2"
            0x01, // NB-ARGS = 1
            0x04, // arg name: "arg1"
            0x61, 0x72, 0x67,
            0x31, // "arg1"
                  // The next bytes are missing, so this is an incomplete frame
                  // 0x08, 0x02, // TYPE=STRING, len = 2
                  // 0x61, 0x62, // "ab"
        ];

        let res = parse_frame(frame);
        assert!(res.is_err(), "Expected an error for incomplete frame");
    }

    // Test that a NOTIFY frame with a message that is longer than the set
    // message length, fails to parse.
    #[test]
    fn test_parse_notify_msg_too_long() {
        let frame: &[u8] = &[
            0x00, 0x00, 0x00, 0x1C, // FRAME-LENGTH = 28 bytes
            0x03, // FRAME-TYPE: NOTIFY
            0x00, 0x00, 0x00, 0x01, // FLAGS = FIN
            0x01, // STREAM-ID = 1
            0x01, // FRAME-ID = 1
            0x04, // message name: "msg1"
            0x6d, 0x73, 0x67, 0x31, // "msg1"
            0x00, // NB-ARGS = 0
            0x04, // message name: "msg2"
            0x6d, 0x73, 0x67, 0x32, // "msg2"
            0x01, // NB-ARGS = 1
            0x04, // arg name: "arg1"
            0x61, 0x72, 0x67, 0x31, // "arg1"
            // Argument is too long by 2 bytes compared to frame-length
            0x08, 0x04, // TYPE=STRING, len = 4
            0x61, 0x62, 0x63, 0x64, // "abcd"
        ];
        let res = parse_frame(frame);
        assert!(res.is_err(), "Expected an error for incomplete frame");
    }
}
