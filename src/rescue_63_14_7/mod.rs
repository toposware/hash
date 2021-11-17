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
#[allow(clippy::needless_range_loop)]
/// Applies exponentiation of the current hash
/// state elements with the Rescue S-Box.
pub fn apply_sbox(state: &mut [Fp]) {
    for i in 0..STATE_WIDTH {
        // alpha = 3
        state[i] *= state[i].square();
    }
}

#[inline(always)]
#[allow(clippy::needless_range_loop)]
/// Applies exponentiation of the current hash state
/// elements with the Rescue inverse S-Box.
pub fn apply_inv_sbox(state: &mut [Fp]) {
    for i in 0..STATE_WIDTH {
        state[i] = state[i].exp_vartime(sbox::INV_ALPHA);
    }
}

#[inline(always)]
#[allow(clippy::needless_range_loop)]
/// Applies matrix-vector multiplication of the current
/// hash state with the Rescue MDS matrix.
pub fn apply_mds(state: &mut [Fp]) {
    let mut result = [Fp::zero(); STATE_WIDTH];
    let mut temp = [Fp::zero(); STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            temp[j] = mds::MDS[i * STATE_WIDTH + j] * state[j];
        }

        for j in 0..STATE_WIDTH {
            result[i] += temp[j];
        }
    }
    state.copy_from_slice(&result);
}

#[inline(always)]
#[allow(clippy::needless_range_loop)]
/// Applies matrix-vector multiplication of the current
/// hash state with the inverse Rescue MDS matrix.
pub fn apply_inv_mds(state: &mut [Fp]) {
    let mut result = [Fp::zero(); STATE_WIDTH];
    let mut temp = [Fp::zero(); STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            temp[j] = mds::INV_MDS[i * STATE_WIDTH + j] * state[j];
        }

        for j in 0..STATE_WIDTH {
            result[i] += temp[j];
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
