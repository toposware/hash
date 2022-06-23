// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::traits::RescuePrimeHasher;
use cheetah::Fp;

/// Digest for Rescue
mod digest;
/// Hasher for Rescue
mod hasher;
/// MDS matrix for Rescue
mod mds;
/// Round constants for Rescue
mod round_constants;
/// S-Box for Rescue
mod sbox;

pub use digest::RescueDigest;
pub use hasher::RescueHash;

// RESCUE CONSTANTS
// ================================================================================================

/// Function state is set to 12 field elements or 96 bytes;
/// 4 elements of the state are reserved for capacity
pub const STATE_WIDTH: usize = 12;
/// 8 elements of the state are reserved for rate
pub const RATE_WIDTH: usize = 8;

/// Seven elements (32-bytes) are returned as digest.
pub const DIGEST_SIZE: usize = 4;

/// The number of rounds is set to 7 to provide 128-bit security level with 40% security margin;
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
pub(crate) fn apply_sbox(state: &mut [Fp; STATE_WIDTH]) {
    state.iter_mut().for_each(|v| {
        let t2 = v.square();
        let t4 = t2.square();
        *v *= t2 * t4;
    });
}

#[inline(always)]
/// Applies exponentiation of the current hash state
/// elements with the Rescue inverse S-Box.
pub(crate) fn apply_inv_sbox(state: &mut [Fp; STATE_WIDTH]) {
    let mut t1 = *state;
    t1.iter_mut().for_each(|t| *t = t.square());

    let mut t2 = t1;
    t2.iter_mut().for_each(|t| *t = t.square());

    let t3 = square_assign_multi_and_multiply::<STATE_WIDTH, 3>(t2, t2);
    let t4 = square_assign_multi_and_multiply::<STATE_WIDTH, 6>(t3, t3);
    let t4 = square_assign_multi_and_multiply::<STATE_WIDTH, 12>(t4, t4);
    let t5 = square_assign_multi_and_multiply::<STATE_WIDTH, 6>(t4, t3);
    let t6 = square_assign_multi_and_multiply::<STATE_WIDTH, 31>(t5, t5);

    for (i, s) in state.iter_mut().enumerate() {
        let a = (t6[i].square() * t5[i]).square().square();
        let b = t1[i] * t2[i] * *s;
        *s = a * b;
    }
}

#[inline(always)]
/// Applies matrix-vector multiplication of the current
/// hash state with the Rescue MDS matrix.
pub(crate) fn apply_mds(state: &mut [Fp; STATE_WIDTH]) {
    let mut result = [Fp::zero(); STATE_WIDTH];
    for (i, r) in result.iter_mut().enumerate() {
        for (j, s) in state.iter().enumerate() {
            *r += mds::MDS[i * STATE_WIDTH + j] * s;
        }
    }

    state.copy_from_slice(&result);
}

// RESCUE PERMUTATION
// ================================================================================================

/// Applies Rescue-XLIX permutation to the provided state.
pub(crate) fn apply_permutation(state: &mut [Fp; STATE_WIDTH]) {
    for i in 0..NUM_HASH_ROUNDS {
        apply_round(state, i);
    }
}

/// Rescue-XLIX round function;
/// implementation based on algorithm 3 of <https://eprint.iacr.org/2020/1143.pdf>
#[inline(always)]
pub(crate) fn apply_round(state: &mut [Fp; STATE_WIDTH], step: usize) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_rescue_sbox() {
        let mut state = [Fp::zero(); STATE_WIDTH];
        let mut rng = OsRng;

        for _ in 0..100 {
            for s in state.iter_mut() {
                *s = Fp::random(&mut rng);
            }

            // Check Forward S-Box

            let mut state_2 = state;
            state_2.iter_mut().for_each(|v| {
                *v = v.exp(sbox::ALPHA as u64);
            });

            apply_sbox(&mut state);

            assert_eq!(state, state_2);

            // Check Backward S-Box

            let mut state_2 = state;
            state_2.iter_mut().for_each(|v| {
                *v = v.exp(sbox::INV_ALPHA);
            });

            apply_inv_sbox(&mut state);

            assert_eq!(state, state_2);
        }
    }
}
