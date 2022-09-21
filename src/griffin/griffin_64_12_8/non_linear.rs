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
    Fp::new(12638892193182228190),
    Fp::new(6831040316949872059),
    Fp::new(1023188440717515928),
    Fp::new(13662080633899744118),
    Fp::new(7854228757667387987),
    Fp::new(2046376881435031856),
    Fp::new(14685269074617260046),
    Fp::new(8877417198384903915),
    Fp::new(3069565322152547784),
    Fp::new(15708457515334775974),
];

/// Constants beta_i for Griffin non-linear layer.
pub(crate) const BETA: [Fp; STATE_WIDTH - 2] = [
    Fp::new(14972816252610083728),
    Fp::new(4551032802196581949),
    Fp::new(5628137787588663305),
    Fp::new(18204131208786327796),
    Fp::new(5385524926960406780),
    Fp::new(4065807080940068899),
    Fp::new(14244977670725314153),
    Fp::new(17476292626901558221),
    Fp::new(13759751949468801103),
    Fp::new(3095355638427042799),
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
