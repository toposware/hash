// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::STATE_WIDTH;
use cheetah::Fp;

#[allow(unused)]
/// Exponent of the Griffin non-linear layer.
pub(crate) const D: u32 = 7;

#[allow(unused)]
/// Inverse exponent.
pub(crate) const INV_D: u64 = 10540996611094048183;

/// Constants alpha_i for Griffin non-linear layer.
pub(crate) const ALPHA: [Fp; STATE_WIDTH - 2] = [
    Fp::new(6303398607380181568),
    Fp::new(12606797214760363136),
    Fp::new(463451752725960383),
    Fp::new(6766850360106141951),
    Fp::new(13070248967486323519),
    Fp::new(926903505451920766),
];

/// Constants beta_i for Griffin non-linear layer.
pub(crate) const BETA: [Fp; STATE_WIDTH - 2] = [
    Fp::new(5698628486727258041),
    Fp::new(4347769877494447843),
    Fp::new(14394168241716153727),
    Fp::new(17391079509977791372),
    Fp::new(13338503682279360778),
    Fp::new(2236440758620861945),
];

#[inline(always)]
/// Squares an element M times, then multiplies it with tail.
pub(crate) fn square_assign_and_multiply<const M: usize>(base: Fp, tail: Fp) -> Fp {
    let mut result = base;
    for _ in 0..M {
        result = result.square();
    }

    result * tail
}

#[inline(always)]
/// Applies exponentiation of the current element by D
pub(crate) fn pow_d(x: &mut Fp) {
    let t2 = x.square();
    let t4 = t2.square();
    *x *= t2 * t4;
}

#[inline(always)]
/// Applies exponentiation of the current element by INV_D
pub(crate) fn pow_inv_d(x: &mut Fp) {
    let t1 = x.square();

    let t2 = t1.square();

    let t3 = square_assign_and_multiply::<3>(t2, t2);
    let t4 = square_assign_and_multiply::<6>(t3, t3);
    let t4 = square_assign_and_multiply::<12>(t4, t4);
    let t5 = square_assign_and_multiply::<6>(t4, t3);
    let t6 = square_assign_and_multiply::<31>(t5, t5);

    let a = (t6.square() * t5).square().square();
    let b = t1 * t2 * *x;
    *x = a * b;
}
