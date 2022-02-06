// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use cheetah::Fp;

/// Digest for Rescue
pub mod digest;
/// Hasher for Rescue
pub mod hasher;
/// MDS matrix for Rescue
pub mod mds;
/// Round constants for Rescue
pub mod round_constants;
/// S-Box for Rescue
pub mod sbox;

// RESCUE CONSTANTS
// ================================================================================================

/// Function state is set to 8 field elements or 64 bytes;
/// 4 elements of the state are reserved for capacity
pub const STATE_WIDTH: usize = 8;
/// 4 elements of the state are reserved for rate
pub const RATE_WIDTH: usize = 4;

/// Seven elements (32-bytes) are returned as digest.
pub const DIGEST_SIZE: usize = 4;

/// The number of rounds is set to 4 to provide 128-bit security level with 40% security margin;
/// computed using algorithm 7 from <https://eprint.iacr.org/2020/1143.pdf>
pub const NUM_HASH_ROUNDS: usize = 7;

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
/// Squares each element of `base` M times, then performs
/// a product term by term with `tail`.
fn square_assign_multi_and_multiply<const N: usize, const M: usize>(
    base: [Fp; N],
    tail: [Fp; N],
) -> [Fp; N] {
    let mut result = base;
    for _ in 0..M {
        result.iter_mut().for_each(|r| *r = r.square());
    }

    result.iter_mut().zip(&tail).for_each(|(r, t)| *r *= t);
    result
}

#[inline(always)]
/// Applies exponentiation of the current hash
/// state elements with the Rescue S-Box.
pub fn apply_sbox(state: &mut [Fp; STATE_WIDTH]) {
    state.iter_mut().for_each(|v| {
        *v *= v.square();
    });
}

#[inline(always)]
/// Applies exponentiation of the current hash state
/// elements with the Rescue inverse S-Box.
pub fn apply_inv_sbox(state: &mut [Fp; STATE_WIDTH]) {
    // found using https://github.com/kwantam/addchain for INV_ALPHA

    let mut t0 = *state;
    let mut t1 = *state;
    t0.iter_mut().for_each(|t| *t = t.square());

    let mut t3 = t0;
    t3.iter_mut().for_each(|t| *t = t.square());

    let mut t2 = square_assign_multi_and_multiply::<STATE_WIDTH, 1>(t3, t0);
    let t4 = square_assign_multi_and_multiply::<STATE_WIDTH, 1>(t1, t1);

    t1 = square_assign_multi_and_multiply::<STATE_WIDTH, 2>(t2, t1);

    let mut t5 = t0;
    t5.iter_mut().zip(&t1).for_each(|(r, t)| *r *= t);

    t2 = square_assign_multi_and_multiply::<STATE_WIDTH, 1>(t1, t4);
    t0.iter_mut().zip(&t2).for_each(|(r, t)| *r *= t);

    t0 = square_assign_multi_and_multiply::<STATE_WIDTH, 8>(t0, t2);
    t0 = square_assign_multi_and_multiply::<STATE_WIDTH, 8>(t0, t2);
    t0 = square_assign_multi_and_multiply::<STATE_WIDTH, 8>(t0, t2);
    t0 = square_assign_multi_and_multiply::<STATE_WIDTH, 8>(t0, t2);
    t0 = square_assign_multi_and_multiply::<STATE_WIDTH, 8>(t0, t2);
    t0 = square_assign_multi_and_multiply::<STATE_WIDTH, 8>(t0, t2);

    *state = square_assign_multi_and_multiply::<STATE_WIDTH, 7>(t0, t5);
}

#[inline(always)]
/// Applies matrix-vector multiplication of the current
/// hash state with the Rescue MDS matrix.
pub fn apply_mds(state: &mut [Fp; STATE_WIDTH]) {
    let mut result = [Fp::zero(); STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            result[i] += mds::MDS[i * STATE_WIDTH + j] * state[j];
        }
    }
    state.copy_from_slice(&result);
}

// RESCUE PERMUTATION
// ================================================================================================

/// Applies Rescue-XLIX permutation to the provided state.
pub fn apply_permutation(state: &mut [Fp; STATE_WIDTH]) {
    for i in 0..NUM_HASH_ROUNDS {
        apply_round(state, i);
    }
}

/// Rescue-XLIX round function;
/// implementation based on algorithm 3 of <https://eprint.iacr.org/2020/1143.pdf>
#[inline(always)]
pub fn apply_round(state: &mut [Fp; STATE_WIDTH], step: usize) {
    // determine which round constants to use
    let ark = round_constants::ARK[step % NUM_HASH_ROUNDS];

    // apply first half of Rescue round
    apply_sbox(state);
    apply_mds(state);
    for i in 0..STATE_WIDTH {
        state[i] += ark[i];
    }

    // apply second half of Rescue round
    apply_inv_sbox(state);
    apply_mds(state);
    for i in 0..STATE_WIDTH {
        state[i] += ark[STATE_WIDTH + i];
    }
}
