// Benchmarks are not production code: panicking on a malformed fixture and casting known-small
// lengths is exactly what we want here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_lossless
)]

//! The full agent loop: decode a NOTIFY, build the ACK that answers it, encode the ACK.
//!
//! This is the per-request cost an SPOA actually pays, and the number worth quoting.
//!
//! Current-API only — it uses `SpopCodec::default()`, which does not exist before 0.12.0, so it
//! cannot be swapped onto an older `src/` for an A/B run. Use `just bench-ab`, which drives
//! `decode.rs` instead, for cross-revision comparisons.
//!
//! Measurements are noisy on a loaded machine — a single pair of runs produced a spread wide
//! enough to change the headline figure by ten points, so alternate several times and compare
//! medians rather than trusting one reading.

use bytes::BytesMut;
use criterion::{Criterion, criterion_group, criterion_main};
use spop::{SpopCodec, actions::VarScope, frames::Ack, parser::parse_frame};
use std::hint::black_box;
use tokio_util::codec::{Decoder, Encoder};

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
    let frame = notify_frame(&[
        ("ip", "192.0.2.1"),
        ("country", "xx"),
        ("user_agent", "curl/8.0.1"),
    ]);

    let mut group = c.benchmark_group("decode");

    group.bench_function("parse_frame/notify_3_args", |b| {
        b.iter(|| parse_frame(black_box(&frame)).expect("parse"));
    });

    // Through the codec, which is how an agent actually sees frames.
    group.bench_function("codec/notify_3_args", |b| {
        b.iter(|| {
            let mut codec = SpopCodec::default();
            let mut buf = BytesMut::from(&frame[..]);
            codec.decode(black_box(&mut buf)).expect("decode")
        });
    });

    group.finish();
}

fn bench_round_trip(c: &mut Criterion) {
    let frame = notify_frame(&[
        ("ip", "192.0.2.1"),
        ("country", "xx"),
        ("user_agent", "curl/8.0.1"),
    ]);

    c.bench_function("round_trip/notify_to_ack", |b| {
        let mut codec = SpopCodec::default();
        let mut dst = BytesMut::with_capacity(256);
        b.iter(|| {
            let mut src = BytesMut::from(&frame[..]);
            let decoded = codec.decode(&mut src).expect("decode").expect("frame");

            let ack = Ack::new(decoded.metadata().stream_id, decoded.metadata().frame_id)
                .set_var(VarScope::Session, "ip_score", 42u32)
                .set_var(VarScope::Transaction, "my_var", "tequila");

            dst.clear();
            codec
                .encode(Box::new(ack), black_box(&mut dst))
                .expect("encode");
        });
    });
}

criterion_group!(benches, bench_decode, bench_round_trip);
criterion_main!(benches);
