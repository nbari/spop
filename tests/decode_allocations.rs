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
use spop::{FramePayload, SpopCodec, TypedDataRef, encode_varint_into};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::Ipv4Addr;
use tokio_util::codec::Decoder;

/// Counts allocations made by the current thread, so tests running in parallel do not interfere.
struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn count_allocation() {
    // `try_with`: the allocator also runs while thread-locals are being torn down.
    let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
}

// SAFETY: every method forwards to `System` unchanged; only a thread-local counter is touched.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, which `System` shares.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated by `System` through this allocator with `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_allocation();
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

fn push_string(buf: &mut Vec<u8>, s: &[u8]) {
    assert!(
        s.len() < 240,
        "fixture strings stay in the 1-byte varint range"
    );
    buf.push(s.len() as u8);
    buf.extend_from_slice(s);
}

fn push_typed_string(buf: &mut Vec<u8>, name: &str, value: &[u8], type_id: u8) {
    push_string(buf, name.as_bytes());
    buf.push(type_id);
    push_string(buf, value);
}

const HEADERS: &[u8] =
    b"\x04host\x0bexample.com\x0auser-agent\x0ecurl/8.11.1-dev\x06accept\x03*/*\x00\x00";

/// A NOTIFY frame shaped like the `check-request` message of a WAF agent: 15 arguments, as
/// `HAProxy` sends them for `args src-ip=src src-port=src_port ... req_id=unique-id`.
fn check_request_frame(stream_id: u8, path: &str) -> Vec<u8> {
    let mut body = vec![
        0x03, // FRAME-TYPE: NOTIFY
        0x00, 0x00, 0x00, 0x01,      // FLAGS: FIN
        stream_id, // STREAM-ID
        0x01,      // FRAME-ID
    ];
    push_string(&mut body, b"check-request");
    body.push(15); // NB-ARGS

    push_string(&mut body, b"src-ip");
    body.extend_from_slice(&[0x06, 192, 0, 2, 1]); // IPV4
    push_string(&mut body, b"src-port");
    body.push(0x02); // INT32
    encode_varint_into(34_672, &mut body);
    push_string(&mut body, b"dst-ip");
    body.extend_from_slice(&[0x06, 198, 51, 100, 7]);
    push_string(&mut body, b"dst-port");
    body.push(0x02);
    encode_varint_into(443, &mut body);
    push_typed_string(&mut body, "method", b"GET", 0x08);
    push_typed_string(&mut body, "path", path.as_bytes(), 0x08);
    push_typed_string(&mut body, "query", b"q=1&page=2", 0x08);
    push_typed_string(&mut body, "version", b"1.1", 0x08);
    push_typed_string(&mut body, "headers", HEADERS, 0x09); // BINARY
    push_string(&mut body, b"body");
    body.push(0x00); // NULL
    push_typed_string(&mut body, "body-mode", b"none", 0x08);
    push_string(&mut body, b"body-complete");
    body.push(0x01); // BOOL false
    push_string(&mut body, b"detect-only");
    body.push(0x11); // BOOL true
    push_typed_string(&mut body, "app", b"policy:default", 0x08);
    push_typed_string(
        &mut body,
        "req_id",
        b"01a1f751-5a7b-7911-90e2-444188eece97",
        0x08,
    );

    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

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
    let mut src = BytesMut::from(&check_request_frame(1, "/api/v4/projects/1/jobs")[..]);

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
    assert_eq!(message.get("src-port"), Some(TypedDataRef::Int32(34_672)));
    assert_eq!(message.get("dst-port"), Some(TypedDataRef::Int32(443)));
    assert_eq!(message.get("method"), Some(TypedDataRef::String("GET")));
    assert_eq!(
        message.get("path"),
        Some(TypedDataRef::String("/api/v4/projects/1/jobs"))
    );
    assert_eq!(message.get("headers"), Some(TypedDataRef::Binary(HEADERS)));
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

    src.extend_from_slice(&check_request_frame(1, "/first"));
    let first = codec.decode(&mut src).expect("decodes").expect("complete");

    // Refill the same buffer, more than once and past its capacity, as a read loop would.
    for stream_id in 2..10 {
        src.extend_from_slice(&check_request_frame(stream_id, &"/later".repeat(30)));
        codec.decode(&mut src).expect("decodes").expect("complete");
    }

    let message = only_message(first.as_ref());
    assert_eq!(message.get("path"), Some(TypedDataRef::String("/first")));
    assert_eq!(message.get("headers"), Some(TypedDataRef::Binary(HEADERS)));
}
