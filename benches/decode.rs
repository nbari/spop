// Benchmarks are not production code: panicking on a malformed fixture and casting known-small
// lengths is exactly what we want here.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_lossless
)]

//! Decode-path benchmark, written to stay compilable across releases.
//!
//! This file touches **only** `parser::parse_frame`, whose signature has been stable across the
//! 0.11 and 0.12 API changes. That is what makes `just bench-ab` work without hand-editing:
//! `src/` can be swapped for any revision and this benchmark still builds.
//!
//! Keep it that way. Anything that reaches for `SpopCodec`, `Ack`, or the `SpopFrame` trait
//! belongs in `roundtrip.rs` or `frames.rs`, which are current-API only.

use criterion::{Criterion, criterion_group, criterion_main};
use spop::parser::parse_frame;
use std::hint::black_box;

/// Appends a SPOP `<STRING>`: varint length prefix then raw bytes.
///
/// Every length used here is below 240, so the varint is a single byte.
fn push_string(buf: &mut Vec<u8>, s: &str) {
    assert!(
        s.len() < 240,
        "bench strings stay in the 1-byte varint range"
    );
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

/// Builds a NOTIFY frame matching `spoe-test.conf`'s `log-request` message.
fn notify_frame(args: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();

    body.push(0x03); // FRAME-TYPE: NOTIFY
    body.extend_from_slice(&1u32.to_be_bytes()); // FLAGS: FIN
    body.push(0x01); // STREAM-ID varint
    body.push(0x01); // FRAME-ID varint

    push_string(&mut body, "log-request");
    body.push(args.len() as u8); // NB-ARGS
    for (key, value) in args {
        push_string(&mut body, key);
        body.push(0x08); // TYPED-DATA: STRING
        push_string(&mut body, value);
    }

    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

/// Builds a NOTIFY frame shaped like a WAF agent's `check-request` message: 15 arguments of
/// mixed types, as `HAProxy` sends `args src-ip=src src-port=src_port ... req_id=unique-id`.
///
/// Integers stay below 240 so that every varint is a single byte without `encode_varint_into`,
/// which older revisions lack.
fn check_request_frame() -> Vec<u8> {
    fn typed_string(body: &mut Vec<u8>, name: &str, type_id: u8, value: &[u8]) {
        push_string(body, name);
        body.push(type_id);
        body.push(value.len() as u8);
        body.extend_from_slice(value);
    }

    let headers: &[u8] =
        b"\x04host\x0bexample.com\x0auser-agent\x0ecurl/8.11.1-dev\x06accept\x03*/*\x00\x00";
    let mut body = vec![0x03, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01]; // NOTIFY, FIN, stream 1, frame 1
    push_string(&mut body, "check-request");
    body.push(15); // NB-ARGS
    push_string(&mut body, "src-ip");
    body.extend_from_slice(&[0x06, 192, 0, 2, 1]); // IPV4
    push_string(&mut body, "src-port");
    body.extend_from_slice(&[0x02, 80]); // INT32
    push_string(&mut body, "dst-ip");
    body.extend_from_slice(&[0x06, 198, 51, 100, 7]);
    push_string(&mut body, "dst-port");
    body.extend_from_slice(&[0x02, 81]);
    typed_string(&mut body, "method", 0x08, b"GET");
    typed_string(&mut body, "path", 0x08, b"/api/v4/projects/1/jobs");
    typed_string(&mut body, "query", 0x08, b"q=1&page=2");
    typed_string(&mut body, "version", 0x08, b"1.1");
    typed_string(&mut body, "headers", 0x09, headers); // BINARY
    push_string(&mut body, "body");
    body.push(0x00); // NULL
    typed_string(&mut body, "body-mode", 0x08, b"none");
    push_string(&mut body, "body-complete");
    body.push(0x01); // BOOL false
    push_string(&mut body, "detect-only");
    body.push(0x11); // BOOL true
    typed_string(&mut body, "app", 0x08, b"policy:default");
    typed_string(
        &mut body,
        "req_id",
        0x08,
        b"01a1f751-5a7b-7911-90e2-444188eece97",
    );

    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

fn bench_decode(c: &mut Criterion) {
    let three_args = notify_frame(&[
        ("ip", "192.0.2.1"),
        ("country", "xx"),
        ("user_agent", "curl/8.0.1"),
    ]);
    let one_arg = notify_frame(&[("ip", "192.0.2.1")]);
    let check_request = check_request_frame();

    let mut group = c.benchmark_group("decode");

    group.bench_function("parse_frame/notify_1_arg", |b| {
        b.iter(|| parse_frame(black_box(&one_arg)).expect("parse"));
    });

    group.bench_function("parse_frame/notify_3_args", |b| {
        b.iter(|| parse_frame(black_box(&three_args)).expect("parse"));
    });

    group.bench_function("parse_frame/notify_15_args_mixed", |b| {
        b.iter(|| parse_frame(black_box(&check_request)).expect("parse"));
    });

    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
