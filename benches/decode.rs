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

fn bench_decode(c: &mut Criterion) {
    let three_args = notify_frame(&[
        ("ip", "192.0.2.1"),
        ("country", "xx"),
        ("user_agent", "curl/8.0.1"),
    ]);
    let one_arg = notify_frame(&[("ip", "192.0.2.1")]);

    let mut group = c.benchmark_group("decode");

    group.bench_function("parse_frame/notify_1_arg", |b| {
        b.iter(|| parse_frame(black_box(&one_arg)).expect("parse"));
    });

    group.bench_function("parse_frame/notify_3_args", |b| {
        b.iter(|| parse_frame(black_box(&three_args)).expect("parse"));
    });

    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
