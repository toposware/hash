// Copyright (c) 2021-2023 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

extern crate hash;
use hash::anemoi_64_8_4;
use hash::traits::Hasher;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("anemoi-64-8-4 - merge", |bench| {
        let v: [anemoi_64_8_4::AnemoiDigest; 2] = [
            anemoi_64_8_4::AnemoiHash::hash(&[1u8]),
            anemoi_64_8_4::AnemoiHash::hash(&[2u8]),
        ];

        bench.iter(|| anemoi_64_8_4::AnemoiHash::merge(black_box(&v)))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark);
criterion_main!(benches);
