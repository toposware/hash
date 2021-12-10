use criterion::{black_box, criterion_group, criterion_main, Criterion};

extern crate hash;
use hash::rescue_63_14_7::{digest::RescueDigest, hasher::RescueHash};
use hash::traits::Hasher;
use rand::thread_rng;
use rand::RngCore;

fn criterion_benchmark(c: &mut Criterion) {
    let v: [RescueDigest; 2] = [RescueHash::hash(&[1u8]), RescueHash::hash(&[2u8])];
    c.bench_function("rescue-63-14-7 - merge", |bench| {
        bench.iter(|| RescueHash::merge(black_box(&v)))
    });

    c.bench_function("rescue-63-14-7 - hash 10KB", |bench| {
        let mut data = vec![0u8; 10 * 1024];
        let mut rng = thread_rng();
        rng.fill_bytes(&mut data);
        bench.iter(|| RescueHash::hash(black_box(&data)))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark);
criterion_main!(benches);
