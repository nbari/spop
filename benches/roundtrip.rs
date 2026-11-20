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
use spop::{
    SpopCodec, SpopFrame, TypedDataRef, actions::VarScope, frames::Ack, parser::parse_frame,
};
use std::hint::black_box;
use tokio_util::codec::{Decoder, Encoder};

#[path = "../tests/support/mod.rs"]
mod support;
use support::{check_request_frame, notify_frame};

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

    // The same through one long-lived codec and read buffer, as `Framed` keeps them: each
    // iteration appends a frame, as a socket read would, then decodes and drops it.
    let two = check_request_frame(1, "/api/v4/projects/1/jobs", 2);
    let ten = check_request_frame(1, "/api/v4/projects/1/jobs", 10);
    for (name, input) in [
        ("notify_3_args", &frame),
        ("mixed_2_headers", &two),
        ("mixed_10_headers", &ten),
    ] {
        group.bench_function(format!("codec_reused_buffer/{name}"), |b| {
            let mut codec = SpopCodec::default();
            let mut buf = BytesMut::with_capacity(8 * 1024);
            b.iter(|| {
                buf.extend_from_slice(input);
                let frame = codec
                    .decode(black_box(&mut buf))
                    .expect("decode")
                    .expect("complete");
                if let spop::FramePayload::ListOfMessages(messages) = frame.payload() {
                    for message in messages {
                        black_box(message.name());
                        message.args().for_each(|arg| {
                            black_box(arg);
                        });
                    }
                }
            });
        });
    }

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

fn bench_ack(c: &mut Criterion) {
    let mut group = c.benchmark_group("two_action_ack");
    for (label, build) in [
        (
            "owned",
            (|| {
                Ack::new(1, 1)
                    .set_var(VarScope::Session, "ip_score", 42u32)
                    .set_var(VarScope::Transaction, "my_var", "tequila")
            }) as fn() -> Ack,
        ),
        ("static", || {
            Ack::new(1, 1)
                .set_var_static(VarScope::Session, "ip_score", TypedDataRef::UInt32(42))
                .set_var_static(
                    VarScope::Transaction,
                    "my_var",
                    TypedDataRef::String("tequila"),
                )
        }),
    ] {
        let mut codec = SpopCodec::default();
        let mut dst = BytesMut::with_capacity(128);
        group.bench_function(label, |b| {
            b.iter(|| {
                dst.clear();
                codec
                    .encode(Box::new(build()), black_box(&mut dst))
                    .unwrap();
            });
        });
    }
}

fn bench_hello(c: &mut Criterion) {
    use spop::{
        Version,
        frame::{FrameFlags, Metadata},
        frames::{FrameCapabilities, HaproxyHello, haproxy_hello::HaproxyHelloFrame},
    };
    let mut group = c.benchmark_group("hello_negotiation");
    for health in [true, false] {
        let hello = HaproxyHelloFrame {
            metadata: Metadata {
                flags: FrameFlags::new(true, false),
                stream_id: 0,
                frame_id: 0,
            },
            payload: HaproxyHello {
                supported_versions: vec![Version::new(2, 0, 0)],
                max_frame_size: 16380,
                capabilities: if health {
                    vec![]
                } else {
                    vec![FrameCapabilities::Pipelining]
                },
                engine_id: (!health).then(|| "example".into()),
                healthcheck: health.then_some(true),
            },
        };
        let wire = hello.serialize().unwrap();
        let (_, frame) = parse_frame(&wire).unwrap();
        let scenario = if health { "healthcheck" } else { "regular" };
        let negotiate = |hello: &HaproxyHello| {
            (
                hello.negotiate_version(),
                hello.negotiate_max_frame_size(16380),
                hello.healthcheck,
            )
        };
        group.bench_function(format!("{scenario}/reparse"), |b| {
            b.iter(|| negotiate(&HaproxyHello::try_from(black_box(&frame).payload()).unwrap()));
        });
        group.bench_function(format!("{scenario}/borrow"), |b| {
            b.iter(|| negotiate(black_box(&frame).as_haproxy_hello().unwrap()));
        });
    }
}

criterion_group!(
    benches,
    bench_decode,
    bench_round_trip,
    bench_ack,
    bench_hello
);
criterion_main!(benches);
