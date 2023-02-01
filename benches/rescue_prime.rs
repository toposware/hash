// Copyright (c) 2021-2023 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

extern crate hash;
use cheetah::Fp;
use hash::traits::Hasher;
use hash::{rescue_64_12_8, rescue_64_8_4};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("rescue-64-8-4 - merge", |bench| {
        let v: [rescue_64_8_4::RescueDigest; 2] = [
            rescue_64_8_4::RescueHash::hash(&[Fp::zero()]),
            rescue_64_8_4::RescueHash::hash(&[Fp::one()]),
        ];

        bench.iter(|| rescue_64_8_4::RescueHash::merge(black_box(&v)))
    });

    c.bench_function("rescue-64-12-8 - merge", |bench| {
        let v: [rescue_64_12_8::RescueDigest; 2] = [
            rescue_64_12_8::RescueHash::hash(&[Fp::zero()]),
            rescue_64_12_8::RescueHash::hash(&[Fp::one()]),
        ];

        bench.iter(|| rescue_64_12_8::RescueHash::merge(black_box(&v)))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark);
criterion_main!(benches);
