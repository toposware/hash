// Copyright (c) 2021 Toposware, Inc.
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

/// Function state is set to 14 field elements or 112 bytes;
/// 7 elements of the state are reserved for capacity
pub const STATE_WIDTH: usize = 14;
/// 7 elements of the state are reserved for rate
pub const RATE_WIDTH: usize = 7;

/// Seven elements (56-bytes) are returned as digest.
pub const DIGEST_SIZE: usize = 7;

/// The number of rounds is set to 7 to provide 128-bit security level with 40% security margin;
/// computed using algorithm 7 from <https://eprint.iacr.org/2020/1143.pdf>
pub const NUM_HASH_ROUNDS: usize = 7;

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
fn square_assign_multi(n: &mut Fp, num_times: usize) {
    for _ in 0..num_times {
        *n = n.square();
    }
}

#[inline(always)]
/// Applies exponentiation of the current hash
/// state elements with the Rescue S-Box.
pub fn apply_sbox(state: &mut [Fp]) {
    for i in 0..STATE_WIDTH {
        // alpha = 3
        state[i] *= state[i].square();
    }
}

#[inline(always)]
/// Applies exponentiation of the current hash state
/// elements with the Rescue inverse S-Box.
pub fn apply_inv_sbox(state: &mut [Fp]) {
    // found using https://github.com/kwantam/addchain for INV_ALPHA
    for i in 0..STATE_WIDTH {
        let mut t1 = state[i]; //           0: 1
        let mut t0 = t1.square(); //        1: 2
        let t3 = t0.square(); //            2: 4
        let mut t2 = t3 * t0; //            3: 6
        t2 = t2 * t3; //                    4: 10
        square_assign_multi(&mut t2, 2); // 6: 40
        t1 *= t2; //                        7: 41
        t2 *= t0; //                        8: 42
        t1 *= t0; //                        9: 43
        t2 *= t1; //                        10: 85
        t0 *= t2; //                        11: 87
        square_assign_multi(&mut t0, 8); // 19: 22272
        t0 *= t2; //                        20: 22357
        square_assign_multi(&mut t0, 8); // 28: 5723392
        t0 *= t2; //                        29: 5723477
        square_assign_multi(&mut t0, 8); // 37: 1465210112
        t0 *= t2; //                        38: 1465210197
        square_assign_multi(&mut t0, 8); // 46: 375093810432
        t0 *= t2; //                        47: 375093810517
        square_assign_multi(&mut t0, 8); // 55: 96024015492352
        t0 *= t2; //                        56: 96024015492437
        square_assign_multi(&mut t0, 8); // 64: 24582147966063872
        t0 *= t2; //                        65: 24582147966063957
        square_assign_multi(&mut t0, 7); // 72: 3146514939656186496
        state[i] = t0 * t1; //              73: 3146514939656186539
    }
}

#[inline(always)]
/// Applies matrix-vector multiplication of the current
/// hash state with the Rescue MDS matrix.
pub fn apply_mds(state: &mut [Fp]) {
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
pub fn apply_round(state: &mut [Fp], step: usize) {
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
