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

#[path = "../tests/support/mod.rs"]
mod support;
use support::{check_request_frame, notify_frame};

fn bench_decode(c: &mut Criterion) {
    let three_args = notify_frame(&[
        ("ip", "192.0.2.1"),
        ("country", "xx"),
        ("user_agent", "curl/8.0.1"),
    ]);
    let one_arg = notify_frame(&[("ip", "192.0.2.1")]);
    let check_request = check_request_frame(1, "/api/v4/projects/1/jobs", 2);

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
