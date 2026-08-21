// Benchmarks are not production code: panicking on a malformed fixture and casting known-small
// lengths is exactly what we want here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::indexing_slicing
)]

//! Encode-path benchmarks that exercise API introduced in 0.12.0.
//!
//! `serialize_then_copy` reproduces the pre-0.12.0 codec path — serialize into a fresh `Vec`,
//! then copy it into the destination — so the reason for the current design stays measurable.
//!
//! Version-comparable benchmarks live in `roundtrip.rs`; this file cannot compile against older
//! releases and is not meant to.

use bytes::{BufMut, BytesMut};
use criterion::{Criterion, criterion_group, criterion_main};
use spop::{SpopCodec, SpopFrame, actions::VarScope, frames::Ack};
use std::hint::black_box;
use tokio_util::codec::Encoder;

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");

    // Allocates a Vec per frame.
    group.bench_function("ack/serialize", |b| {
        b.iter(|| {
            let ack = Ack::new(1, 1)
                .set_var(VarScope::Session, "ip_score", 42u32)
                .set_var(VarScope::Transaction, "my_var", "tequila");
            black_box(ack.serialize().expect("serialize"))
        });
    });

    // Appends to a reused buffer, the way the codec now does: no per-frame allocation.
    group.bench_function("ack/serialize_into", |b| {
        let mut dst = Vec::with_capacity(256);
        b.iter(|| {
            dst.clear();
            let ack = Ack::new(1, 1)
                .set_var(VarScope::Session, "ip_score", 42u32)
                .set_var(VarScope::Transaction, "my_var", "tequila");
            ack.serialize_into(black_box(&mut dst))
                .expect("serialize_into");
        });
    });

    // The pre-0.12.0 codec path: serialize into a fresh Vec, then copy it into the
    // destination. This is what `serialize_into` replaces.
    group.bench_function("ack/serialize_then_copy", |b| {
        let mut dst = BytesMut::with_capacity(256);
        b.iter(|| {
            dst.clear();
            let ack = Ack::new(1, 1)
                .set_var(VarScope::Session, "ip_score", 42u32)
                .set_var(VarScope::Transaction, "my_var", "tequila");
            let serialized = ack.serialize().expect("serialize");
            dst.put_slice(black_box(&serialized));
        });
    });

    // Full codec write path, reusing the buffer as `Framed` does.
    group.bench_function("codec/ack", |b| {
        let mut codec = SpopCodec::default();
        let mut dst = BytesMut::with_capacity(256);
        b.iter(|| {
            dst.clear();
            let ack = Ack::new(1, 1)
                .set_var(VarScope::Session, "ip_score", 42u32)
                .set_var(VarScope::Transaction, "my_var", "tequila");
            codec
                .encode(Box::new(ack), black_box(&mut dst))
                .expect("encode");
        });
    });

    // Larger frame: the staging copy scales with size, the per-write bookkeeping does not.
    let big_value = "x".repeat(200);
    group.bench_function("ack_large/serialize_then_copy", |b| {
        let mut dst = BytesMut::with_capacity(4096);
        b.iter(|| {
            dst.clear();
            let mut ack = Ack::new(1, 1);
            for i in 0u32..16 {
                ack = ack.set_var(VarScope::Session, "var", big_value.as_str());
                ack = ack.set_var(VarScope::Transaction, "n", i);
            }
            let serialized = ack.serialize().expect("serialize");
            dst.put_slice(black_box(&serialized));
        });
    });

    group.bench_function("ack_large/serialize_into", |b| {
        let mut dst = Vec::with_capacity(4096);
        b.iter(|| {
            dst.clear();
            let mut ack = Ack::new(1, 1);
            for i in 0u32..16 {
                ack = ack.set_var(VarScope::Session, "var", big_value.as_str());
                ack = ack.set_var(VarScope::Transaction, "n", i);
            }
            ack.serialize_into(black_box(&mut dst))
                .expect("serialize_into");
        });
    });

    group.finish();
}

criterion_group!(benches, bench_encode);
criterion_main!(benches);
