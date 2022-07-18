// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::traits::RescuePrimeHasher;
use cheetah::Fp;

use crate::f64_utils::{apply_rescue_inv_sbox, apply_rescue_sbox};

/// Digest for Rescue
mod digest;
/// Hasher for Rescue
mod hasher;
/// MDS matrix for Rescue
mod mds;
/// Round constants for Rescue
mod round_constants;

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
/// Applies matrix-vector multiplication of the current
/// hash state with the Rescue MDS matrix.
pub(crate) fn apply_mds(state: &mut [Fp; STATE_WIDTH]) {
    let mut result = [Fp::zero(); STATE_WIDTH];

    // Using the linearity of the operations we can split the state into a low||high decomposition
    // and operate on each with no overflow and then combine/reduce the result to a field element.
    let mut state_l = [0u64; STATE_WIDTH];
    let mut state_h = [0u64; STATE_WIDTH];

    for r in 0..STATE_WIDTH {
        let s = state[r].output_unreduced_internal();
        state_h[r] = s >> 32;
        state_l[r] = (s as u32) as u64;
    }

    let state_h = mds::mds_multiply_freq(state_h);
    let state_l = mds::mds_multiply_freq(state_l);

    for r in 0..STATE_WIDTH {
        let s = state_l[r] as u128 + ((state_h[r] as u128) << 32);

        // s fits in 96 bits, hence we can reduce it appropriately.
        // Calling Fp::from_raw_unchecked() is then safe.
        result[r] = Fp::from_raw_unchecked(cheetah::fp_arith_utils::reduce_u96(s));
    }
    *state = result;
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
    apply_rescue_sbox(state);
    apply_mds(state);
    for i in 0..STATE_WIDTH {
        state[i] += ark[i];
    }

    // apply second half of Rescue round
    apply_rescue_inv_sbox(state);
    apply_mds(state);
    for i in 0..STATE_WIDTH {
        state[i] += ark[STATE_WIDTH + i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    const INV_MDS: [Fp; STATE_WIDTH * STATE_WIDTH] = [
        Fp::new(14868391535953158196),
        Fp::new(13278298489594233127),
        Fp::new(389999932707070822),
        Fp::new(9782021734907796003),
        Fp::new(4829905704463175582),
        Fp::new(7567822018949214430),
        Fp::new(14205019324568680367),
        Fp::new(15489674211196160593),
        Fp::new(17636013826542227504),
        Fp::new(16254215311946436093),
        Fp::new(3641486184877122796),
        Fp::new(11069068059762973582),
        Fp::new(11069068059762973582),
        Fp::new(14868391535953158196),
        Fp::new(13278298489594233127),
        Fp::new(389999932707070822),
        Fp::new(9782021734907796003),
        Fp::new(4829905704463175582),
        Fp::new(7567822018949214430),
        Fp::new(14205019324568680367),
        Fp::new(15489674211196160593),
        Fp::new(17636013826542227504),
        Fp::new(16254215311946436093),
        Fp::new(3641486184877122796),
        Fp::new(3641486184877122796),
        Fp::new(11069068059762973582),
        Fp::new(14868391535953158196),
        Fp::new(13278298489594233127),
        Fp::new(389999932707070822),
        Fp::new(9782021734907796003),
        Fp::new(4829905704463175582),
        Fp::new(7567822018949214430),
        Fp::new(14205019324568680367),
        Fp::new(15489674211196160593),
        Fp::new(17636013826542227504),
        Fp::new(16254215311946436093),
        Fp::new(16254215311946436093),
        Fp::new(3641486184877122796),
        Fp::new(11069068059762973582),
        Fp::new(14868391535953158196),
        Fp::new(13278298489594233127),
        Fp::new(389999932707070822),
        Fp::new(9782021734907796003),
        Fp::new(4829905704463175582),
        Fp::new(7567822018949214430),
        Fp::new(14205019324568680367),
        Fp::new(15489674211196160593),
        Fp::new(17636013826542227504),
        Fp::new(17636013826542227504),
        Fp::new(16254215311946436093),
        Fp::new(3641486184877122796),
        Fp::new(11069068059762973582),
        Fp::new(14868391535953158196),
        Fp::new(13278298489594233127),
        Fp::new(389999932707070822),
        Fp::new(9782021734907796003),
        Fp::new(4829905704463175582),
        Fp::new(7567822018949214430),
        Fp::new(14205019324568680367),
        Fp::new(15489674211196160593),
        Fp::new(15489674211196160593),
        Fp::new(17636013826542227504),
        Fp::new(16254215311946436093),
        Fp::new(3641486184877122796),
        Fp::new(11069068059762973582),
        Fp::new(14868391535953158196),
        Fp::new(13278298489594233127),
        Fp::new(389999932707070822),
        Fp::new(9782021734907796003),
        Fp::new(4829905704463175582),
        Fp::new(7567822018949214430),
        Fp::new(14205019324568680367),
        Fp::new(14205019324568680367),
        Fp::new(15489674211196160593),
        Fp::new(17636013826542227504),
        Fp::new(16254215311946436093),
        Fp::new(3641486184877122796),
        Fp::new(11069068059762973582),
        Fp::new(14868391535953158196),
        Fp::new(13278298489594233127),
        Fp::new(389999932707070822),
        Fp::new(9782021734907796003),
        Fp::new(4829905704463175582),
        Fp::new(7567822018949214430),
        Fp::new(7567822018949214430),
        Fp::new(14205019324568680367),
        Fp::new(15489674211196160593),
        Fp::new(17636013826542227504),
        Fp::new(16254215311946436093),
        Fp::new(3641486184877122796),
        Fp::new(11069068059762973582),
        Fp::new(14868391535953158196),
        Fp::new(13278298489594233127),
        Fp::new(389999932707070822),
        Fp::new(9782021734907796003),
        Fp::new(4829905704463175582),
        Fp::new(4829905704463175582),
        Fp::new(7567822018949214430),
        Fp::new(14205019324568680367),
        Fp::new(15489674211196160593),
        Fp::new(17636013826542227504),
        Fp::new(16254215311946436093),
        Fp::new(3641486184877122796),
        Fp::new(11069068059762973582),
        Fp::new(14868391535953158196),
        Fp::new(13278298489594233127),
        Fp::new(389999932707070822),
        Fp::new(9782021734907796003),
        Fp::new(9782021734907796003),
        Fp::new(4829905704463175582),
        Fp::new(7567822018949214430),
        Fp::new(14205019324568680367),
        Fp::new(15489674211196160593),
        Fp::new(17636013826542227504),
        Fp::new(16254215311946436093),
        Fp::new(3641486184877122796),
        Fp::new(11069068059762973582),
        Fp::new(14868391535953158196),
        Fp::new(13278298489594233127),
        Fp::new(389999932707070822),
        Fp::new(389999932707070822),
        Fp::new(9782021734907796003),
        Fp::new(4829905704463175582),
        Fp::new(7567822018949214430),
        Fp::new(14205019324568680367),
        Fp::new(15489674211196160593),
        Fp::new(17636013826542227504),
        Fp::new(16254215311946436093),
        Fp::new(3641486184877122796),
        Fp::new(11069068059762973582),
        Fp::new(14868391535953158196),
        Fp::new(13278298489594233127),
        Fp::new(13278298489594233127),
        Fp::new(389999932707070822),
        Fp::new(9782021734907796003),
        Fp::new(4829905704463175582),
        Fp::new(7567822018949214430),
        Fp::new(14205019324568680367),
        Fp::new(15489674211196160593),
        Fp::new(17636013826542227504),
        Fp::new(16254215311946436093),
        Fp::new(3641486184877122796),
        Fp::new(11069068059762973582),
        Fp::new(14868391535953158196),
    ];

    /// Applies matrix-vector multiplication of the current
    /// hash state with the inverse Rescue MDS matrix.
    fn apply_inv_mds(state: &mut [Fp; STATE_WIDTH]) {
        let mut result = [Fp::zero(); STATE_WIDTH];
        for (i, r) in result.iter_mut().enumerate() {
            for (j, s) in state.iter().enumerate() {
                *r += INV_MDS[i * STATE_WIDTH + j] * s;
            }
        }

        state.copy_from_slice(&result);
    }

    #[test]
    fn test_mds() {
        let mut state = [Fp::zero(); STATE_WIDTH];
        let mut rng = OsRng;

        for _ in 0..100 {
            for s in state.iter_mut() {
                *s = Fp::random(&mut rng);
            }

            let state_copy = state;
            apply_mds(&mut state);

            // Check that matrix multiplication was consistent
            apply_inv_mds(&mut state);
            assert_eq!(state, state_copy);
        }
    }
}
