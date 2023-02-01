// Copyright (c) 2021-2023 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

extern crate hash;
use hash::traits::Hasher;
use hash::{griffin_64_12_8, griffin_64_8_4};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("griffin-64-8-4 - merge", |bench| {
        let v: [griffin_64_8_4::GriffinDigest; 2] = [
            griffin_64_8_4::GriffinHash::hash(&[1u8]),
            griffin_64_8_4::GriffinHash::hash(&[2u8]),
        ];

        bench.iter(|| griffin_64_8_4::GriffinHash::merge(black_box(&v)))
    });

    c.bench_function("griffin-64-12-8 - merge", |bench| {
        let v: [griffin_64_12_8::GriffinDigest; 2] = [
            griffin_64_12_8::GriffinHash::hash(&[1u8]),
            griffin_64_12_8::GriffinHash::hash(&[2u8]),
        ];

        bench.iter(|| griffin_64_12_8::GriffinHash::merge(black_box(&v)))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark);
criterion_main!(benches);
