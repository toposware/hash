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

/// Function state is set to 8 field elements or 64 bytes;
/// 4 elements of the state are reserved for capacity
pub const STATE_WIDTH: usize = 8;
/// 4 elements of the state are reserved for rate
pub const RATE_WIDTH: usize = 4;

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

    const INV_MDS: [Fp; STATE_WIDTH * STATE_WIDTH] = [
        Fp::new(736023694432405199),
        Fp::new(8182972243258059710),
        Fp::new(3498051006941954835),
        Fp::new(17162055534186847493),
        Fp::new(3768423433765138740),
        Fp::new(11503737910687402654),
        Fp::new(1453219729342325084),
        Fp::new(9035748655629619249),
        Fp::new(15693091329388750858),
        Fp::new(2573505753597974022),
        Fp::new(15745159230526333895),
        Fp::new(6686448110042837653),
        Fp::new(4703662890575546906),
        Fp::new(9916617752772351520),
        Fp::new(5528098920813017414),
        Fp::new(12940392289941525017),
        Fp::new(17745064910773280016),
        Fp::new(797434693060697420),
        Fp::new(5264502565591282528),
        Fp::new(13421417760019661442),
        Fp::new(2531125835183648429),
        Fp::new(10215801464183102177),
        Fp::new(13320883810044252580),
        Fp::new(10490745238802412693),
        Fp::new(13493004860061390160),
        Fp::new(9141779445896724328),
        Fp::new(8663329072260147678),
        Fp::new(11949007539381617003),
        Fp::new(11905189282259646646),
        Fp::new(9053033456546638156),
        Fp::new(10555764414940492586),
        Fp::new(17472612275726265049),
        Fp::new(17282312527066577647),
        Fp::new(3183627701138979025),
        Fp::new(17441045567048219569),
        Fp::new(14021888144787377217),
        Fp::new(68208443019285159),
        Fp::new(17083767579863181537),
        Fp::new(7523887749186067568),
        Fp::new(15628982634963233884),
        Fp::new(9611158784006141084),
        Fp::new(1369172041706808649),
        Fp::new(15668078875424249322),
        Fp::new(12124654295076732612),
        Fp::new(11234713694116848515),
        Fp::new(15845246860400413992),
        Fp::new(6096425342602242220),
        Fp::new(1837526384324900891),
        Fp::new(1704968375846022558),
        Fp::new(18421938878397970569),
        Fp::new(5460387332071102602),
        Fp::new(7170422060048660548),
        Fp::new(2601576556945010044),
        Fp::new(3102141129998913266),
        Fp::new(16413708698593952625),
        Fp::new(465089176342120752),
        Fp::new(13178933673652877755),
        Fp::new(6530780806989649095),
        Fp::new(8973909305075134254),
        Fp::new(18308669672380093672),
        Fp::new(10779850691477795951),
        Fp::new(7037270482897111650),
        Fp::new(7258305005278376908),
        Fp::new(1719256639907298000),
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
    fn test_square_assign_multi_and_multiply() {
        let mut state = [Fp::zero(); STATE_WIDTH];
        let zeros = [Fp::zero(); STATE_WIDTH];
        let ones = [Fp::one(); STATE_WIDTH];
        let mut rng = OsRng;

        for _ in 0..10 {
            for s in state.iter_mut() {
                *s = Fp::random(&mut rng);
            }

            assert_eq!(
                square_assign_multi_and_multiply::<STATE_WIDTH, 0>(state, zeros),
                zeros
            );
            assert_eq!(
                square_assign_multi_and_multiply::<STATE_WIDTH, 0>(zeros, state),
                zeros
            );
            assert_eq!(
                square_assign_multi_and_multiply::<STATE_WIDTH, 0>(ones, ones),
                ones
            );
            assert_eq!(
                square_assign_multi_and_multiply::<STATE_WIDTH, 0>(state, ones),
                state
            );

            assert_eq!(
                square_assign_multi_and_multiply::<STATE_WIDTH, 1>(state, zeros),
                zeros
            );
            assert_eq!(
                square_assign_multi_and_multiply::<STATE_WIDTH, 1>(zeros, state),
                zeros
            );
            assert_eq!(
                square_assign_multi_and_multiply::<STATE_WIDTH, 1>(ones, ones),
                ones
            );
        }
    }

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
