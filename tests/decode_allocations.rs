// Test code: panicking on a malformed fixture and casting known-small lengths is intended.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

//! How many allocations decoding one NOTIFY frame through [`SpopCodec`] costs.
//!
//! Every argument name and every STRING or BINARY value used to be copied into its own `String`
//! or `Vec`, so the count grew with the number of arguments: 27 allocations for the frame below.
//! Messages now point into the frame instead, which leaves a fixed handful per frame.

use bytes::BytesMut;
use spop::{FramePayload, SpopCodec, TypedDataRef};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::Ipv4Addr;
use tokio_util::codec::Decoder;

/// Counts allocations made by the current thread, so tests running in parallel do not interfere.
struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static REQUESTED_BYTES: Cell<usize> = const { Cell::new(0) };
}

fn count_allocation(bytes: usize) {
    // `try_with`: the allocator also runs while thread-locals are being torn down.
    let _ = REQUESTED_BYTES.try_with(|total| total.set(total.get().wrapping_add(bytes)));
    let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
}

// SAFETY: every method forwards to `System` unchanged; only a thread-local counter is touched.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation(layout.size());
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, which `System` shares.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated by `System` through this allocator with `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation(layout.size());
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_allocation(new_size);
        // SAFETY: `ptr` and `layout` come from this allocator; the caller upholds the rest.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn allocations_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = ALLOCATIONS.with(Cell::get);
    let result = f();
    (result, ALLOCATIONS.with(Cell::get) - before)
}

mod support;
use support::{check_request_frame, headers, notify_frame};

fn only_message(frame: &dyn spop::SpopFrame) -> spop::frame::Message {
    let FramePayload::ListOfMessages(messages) = frame.payload() else {
        panic!("expected a list of messages");
    };
    assert_eq!(messages.len(), 1);
    messages.first().cloned().expect("one message")
}

#[test]
fn decoding_a_notify_frame_allocates_a_fixed_handful() {
    let mut codec = SpopCodec::default();
    let mut src = BytesMut::from(&check_request_frame(1, "/api/v4/projects/1/jobs", 2)[..]);

    let (decoded, allocations) = allocations_during(|| codec.decode(&mut src));
    let frame = decoded.expect("decodes").expect("a complete frame");
    assert!(src.is_empty(), "the whole frame is consumed");

    // The frame box, the message list, the argument list, and the header `bytes` adds when the
    // frame is split off the read buffer. Names and values point into the frame.
    assert!(
        allocations <= 4,
        "decoding a 15-argument NOTIFY frame made {allocations} allocations"
    );

    let message = only_message(frame.as_ref());
    assert_eq!(message.name(), "check-request");
    assert_eq!(message.args().len(), 15);
    assert_eq!(
        message.get("src-ip"),
        Some(TypedDataRef::IPv4(Ipv4Addr::new(192, 0, 2, 1)))
    );
    assert_eq!(message.get("src-port"), Some(TypedDataRef::Int32(80)));
    assert_eq!(message.get("dst-port"), Some(TypedDataRef::Int32(81)));
    assert_eq!(message.get("method"), Some(TypedDataRef::String("GET")));
    assert_eq!(
        message.get("path"),
        Some(TypedDataRef::String("/api/v4/projects/1/jobs"))
    );
    assert_eq!(
        message.get("headers"),
        Some(TypedDataRef::Binary(&headers(2)))
    );
    assert_eq!(message.get("body"), Some(TypedDataRef::Null));
    assert_eq!(
        message.get("body-complete"),
        Some(TypedDataRef::Bool(false))
    );
    assert_eq!(message.get("detect-only"), Some(TypedDataRef::Bool(true)));
    assert_eq!(
        message.get("req_id"),
        Some(TypedDataRef::String("01a1f751-5a7b-7911-90e2-444188eece97"))
    );
}

/// Decoded values must stay intact while the codec keeps reading into the same buffer.
#[test]
fn decoded_values_outlive_later_reads_into_the_buffer() {
    let mut codec = SpopCodec::default();
    let mut src = BytesMut::new();

    src.extend_from_slice(&check_request_frame(1, "/first", 2));
    let first = codec.decode(&mut src).expect("decodes").expect("complete");

    // Refill the same buffer, more than once and past its capacity, as a read loop would.
    for stream_id in 2..10 {
        src.extend_from_slice(&check_request_frame(stream_id, &"/later".repeat(30), 2));
        codec.decode(&mut src).expect("decodes").expect("complete");
    }

    let message = only_message(first.as_ref());
    assert_eq!(message.get("path"), Some(TypedDataRef::String("/first")));
    assert_eq!(
        message.get("headers"),
        Some(TypedDataRef::Binary(&headers(2)))
    );
}

#[test]
fn rejecting_an_outbound_frame_preserves_read_ahead() {
    use spop::{SpopFrame, frames::Ack, parser::parse_frame};
    let outbound = Ack::new(1, 1).serialize().unwrap();
    let reject = |tail: Vec<u8>| {
        let wire = [outbound.as_slice(), &tail].concat();
        let mut src = BytesMut::from(wire.as_slice());
        let original = src.as_ptr();
        let before = REQUESTED_BYTES.with(Cell::get);
        let (error, calls) =
            allocations_during(|| SpopCodec::default().decode(&mut src).unwrap_err());
        let bytes = REQUESTED_BYTES.with(Cell::get).wrapping_sub(before);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "Failed to parse frame: NoneOf at byte 4");
        assert_eq!(&src[..], wire);
        assert_eq!(src.as_ptr(), original, "read-ahead was relocated");

        let Err(nom::Err::Failure(error)) = parse_frame(&wire) else {
            panic!("expected a direction error");
        };
        assert_eq!(error.input, wire.get(4..).unwrap());
        (calls, bytes)
    };
    assert_eq!(
        reject(notify_frame(&[])),
        reject(check_request_frame(2, "/next", 10))
    );
}

#[test]
fn reading_every_field_has_a_fixed_allocation_budget() {
    for (count, wire) in [
        (1, notify_frame(&[("ip", "192.0.2.1")])),
        (
            3,
            notify_frame(&[("ip", "::1"), ("", "first"), ("", "second")]),
        ),
        (15, check_request_frame(1, "/", 2)),
        (15, check_request_frame(1, "/", 10)),
    ] {
        let mut src = BytesMut::from(wire.as_slice());
        let ((), allocations) = allocations_during(|| {
            let frame = SpopCodec::default().decode(&mut src).unwrap().unwrap();
            let FramePayload::ListOfMessages(messages) = frame.payload() else {
                panic!("NOTIFY")
            };
            let message = messages.first().unwrap();
            std::hint::black_box(message.name());
            assert_eq!(
                message
                    .args()
                    .inspect(|arg| {
                        std::hint::black_box(arg);
                    })
                    .count(),
                count
            );
        });
        assert!(
            allocations <= 4,
            "{count} fields used {allocations} allocations"
        );
    }
}

#[test]
fn partial_and_coalesced_frames_preserve_boundaries() {
    let first = notify_frame(&[("path", "/café")]);
    let second = check_request_frame(2, "/two", 10);
    let mut codec = SpopCodec::new(u32::try_from(first.len() - 4).unwrap());
    for split in 0..first.len() {
        let (prefix, rest) = first.split_at(split);
        let mut src = BytesMut::from(prefix);
        assert!(codec.decode(&mut src).unwrap().is_none());
        assert_eq!(&src[..], prefix);
        src.extend_from_slice(rest);
        src.extend_from_slice(&second);
        let parsed = codec.decode(&mut src).unwrap().unwrap();
        assert_eq!(
            only_message(&*parsed).get("path"),
            Some(TypedDataRef::String("/café"))
        );
        assert_eq!(&src[..], second);
        assert!(matches!(
            spop::parser::parse_frame(prefix),
            Err(nom::Err::Incomplete(_))
        ));
        let mut next_codec = SpopCodec::default();
        assert_eq!(
            next_codec
                .decode(&mut src)
                .unwrap()
                .unwrap()
                .metadata()
                .stream_id,
            2
        );
        assert!(src.is_empty());
    }
}

#[test]
fn hello_and_disconnect_decode_without_a_receive_buffer_allocation() {
    use spop::{
        SpopFrame, Version,
        frame::{FrameFlags, Metadata},
        frames::{
            FrameCapabilities, HaproxyDisconnect, HaproxyHello,
            haproxy_disconnect::HaproxyDisconnectFrame, haproxy_hello::HaproxyHelloFrame,
        },
    };
    let metadata = Metadata {
        flags: FrameFlags::new(true, false),
        stream_id: 0,
        frame_id: 0,
    };
    let disconnect = HaproxyDisconnectFrame {
        metadata,
        payload: HaproxyDisconnect {
            status_code: 0,
            message: "normal".into(),
        },
    }
    .serialize()
    .unwrap();
    for healthcheck in [false, true] {
        let hello = HaproxyHelloFrame {
            metadata,
            payload: HaproxyHello {
                supported_versions: vec![Version::new(2, 0, 0)],
                capabilities: vec![FrameCapabilities::Pipelining],
                max_frame_size: 16_380,
                engine_id: (!healthcheck).then(|| "example".into()),
                healthcheck: healthcheck.then_some(true),
            },
        }
        .serialize()
        .unwrap();
        let mut src = BytesMut::from(&hello[..]);
        let (frame, calls) =
            allocations_during(|| SpopCodec::default().decode(&mut src).unwrap().unwrap());
        let (_, slice_calls) = allocations_during(|| spop::parser::parse_frame(&hello).unwrap());
        assert!(
            calls <= 13 && slice_calls <= 13,
            "HELLO codec={calls} parser={slice_calls}"
        );
        let (result, extra) = allocations_during(|| {
            let parsed = frame.as_haproxy_hello().unwrap();
            (
                parsed.negotiate_version(),
                parsed.negotiate_max_frame_size(20_000),
                parsed.healthcheck,
            )
        });
        assert_eq!(
            result,
            (
                Some(Version::new(2, 0, 0)),
                Ok(16_380),
                healthcheck.then_some(true)
            )
        );
        assert_eq!(extra, 0);
    }
    let mut src = BytesMut::from(&disconnect[..]);
    let (frame, calls) =
        allocations_during(|| SpopCodec::default().decode(&mut src).unwrap().unwrap());
    let (_, slice_calls) = allocations_during(|| spop::parser::parse_frame(&disconnect).unwrap());
    assert!(frame.as_haproxy_hello().is_none());
    assert!(
        calls <= 6 && slice_calls <= 6,
        "DISCONNECT codec={calls} parser={slice_calls}"
    );
}

#[test]
fn static_ack_uses_two_allocations_and_matches_owned_actions() {
    use spop::{SpopFrame, VarScope, frames::Ack};
    use tokio_util::codec::Encoder;
    let mut codec = SpopCodec::default();
    let mut dst = BytesMut::with_capacity(128);
    let owned = Ack::new(2, 3)
        .set_var(VarScope::Session, "ip_score", 42u32)
        .set_var(VarScope::Transaction, "my_var", "tequila");
    let expected = owned.serialize().unwrap();
    codec.encode(Box::new(owned), &mut dst).unwrap();
    dst.clear();
    let ((), calls) = allocations_during(|| {
        let frame = Ack::new(2, 3)
            .set_var_static(VarScope::Session, "ip_score", TypedDataRef::UInt32(42))
            .set_var_static(
                VarScope::Transaction,
                "my_var",
                TypedDataRef::String("tequila"),
            );
        codec.encode(Box::new(frame), &mut dst).unwrap();
    });
    assert_eq!(&dst[..], expected);
    assert!(calls <= 2, "{calls} allocations");
}

#[test]
fn lossy_and_empty_fields_survive_reuse_and_conversion() {
    // Two messages, including an empty message name, an unnamed value, and raw binary.
    let body = [
        3, 0, 0, 0, 1, 1, 1, 1, 0xff, 2, 0, 8, 2, b'a', 0xff, 1, b'b', 9, 2, 0xff, 0, 0, 1, 0, 8, 0,
    ];
    let mut src = BytesMut::from(&(body.len() as u32).to_be_bytes()[..]);
    src.extend_from_slice(&body);
    let frame = SpopCodec::default().decode(&mut src).unwrap().unwrap();
    let FramePayload::ListOfMessages(messages) = frame.payload() else {
        panic!("NOTIFY")
    };
    let [first, second] = messages else {
        panic!("expected two messages")
    };
    assert_eq!(first.name(), "�");
    assert_eq!(second.name(), "");
    assert_eq!(second.get(""), Some(TypedDataRef::String("")));
    let value = first.get("").unwrap().into_owned();
    let retained = first.clone();
    drop(frame);
    src.extend_from_slice(&check_request_frame(2, "/later", 10));
    SpopCodec::default().decode(&mut src).unwrap().unwrap();
    assert_eq!(value, spop::TypedData::String("a�".into()));
    assert_eq!(retained.get("b"), Some(TypedDataRef::Binary(&[0xff, 0])));
}
