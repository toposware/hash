// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

extern crate hash;
use cheetah::Fp;
use hash::griffin_64_12_8::{GriffinDigest, GriffinHash};
use hash::traits::Hasher;
use rand_core::OsRng;
use rand_core::RngCore;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("griffin-64-12-8 - merge", |bench| {
        let v: [GriffinDigest; 2] = [GriffinHash::hash(&[1u8]), GriffinHash::hash(&[2u8])];

        bench.iter(|| GriffinHash::merge(black_box(&v)))
    });

    c.bench_function("griffin-64-12-8 - hash 25 Fp elements", |bench| {
        let mut v = [Fp::zero(); 25];
        let mut rng = OsRng;
        for e in v.iter_mut() {
            *e = Fp::random(&mut rng);
        }

        bench.iter(|| GriffinHash::hash_field(black_box(&v)))
    });

    c.bench_function("griffin-64-12-8 - hash 10KB", |bench| {
        let mut data = vec![0u8; 10 * 1024];
        let mut rng = OsRng;
        rng.fill_bytes(&mut data);

        bench.iter(|| GriffinHash::hash(black_box(&data)))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark);
criterion_main!(benches);
