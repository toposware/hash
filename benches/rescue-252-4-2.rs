use criterion::{black_box, criterion_group, criterion_main, Criterion};

extern crate hash;
use hash::rescue_252_4_2::{digest::RescueDigest, hasher::RescueHash};
use hash::traits::Hasher;

fn criterion_benchmark(c: &mut Criterion) {
    let v: [RescueDigest; 2] = [RescueHash::hash(&[1u8]), RescueHash::hash(&[2u8])];
    c.bench_function("rescue-252-4-2 - merge", |bench| {
        bench.iter(|| RescueHash::merge(black_box(&v)))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark);
criterion_main!(benches);
