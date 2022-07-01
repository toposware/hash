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

    const INV_MDS: [Fp; STATE_WIDTH * STATE_WIDTH] = [
        Fp::new(1025714968950054217),
        Fp::new(2820417286206414279),
        Fp::new(4993698564949207576),
        Fp::new(12970218763715480197),
        Fp::new(15096702659601816313),
        Fp::new(5737881372597660297),
        Fp::new(13327263231927089804),
        Fp::new(4564252978131632277),
        Fp::new(16119054824480892382),
        Fp::new(6613927186172915989),
        Fp::new(6454498710731601655),
        Fp::new(2510089799608156620),
        Fp::new(14311337779007263575),
        Fp::new(10306799626523962951),
        Fp::new(7776331823117795156),
        Fp::new(4922212921326569206),
        Fp::new(8669179866856828412),
        Fp::new(936244772485171410),
        Fp::new(4077406078785759791),
        Fp::new(2938383611938168107),
        Fp::new(16650590241171797614),
        Fp::new(16578411244849432284),
        Fp::new(17600191004694808340),
        Fp::new(5913375445729949081),
        Fp::new(13640353831792923980),
        Fp::new(1583879644687006251),
        Fp::new(17678309436940389401),
        Fp::new(6793918274289159258),
        Fp::new(3594897835134355282),
        Fp::new(2158539885379341689),
        Fp::new(12473871986506720374),
        Fp::new(14874332242561185932),
        Fp::new(16402478875851979683),
        Fp::new(9893468322166516227),
        Fp::new(8142413325661539529),
        Fp::new(3444000755516388321),
        Fp::new(14009777257506018221),
        Fp::new(18218829733847178457),
        Fp::new(11151899210182873569),
        Fp::new(14653120475631972171),
        Fp::new(9591156713922565586),
        Fp::new(16622517275046324812),
        Fp::new(3958136700677573712),
        Fp::new(2193274161734965529),
        Fp::new(15125079516929063010),
        Fp::new(3648852869044193741),
        Fp::new(4405494440143722315),
        Fp::new(15549070131235639125),
        Fp::new(14324333194410783741),
        Fp::new(12565645879378458115),
        Fp::new(4028590290335558535),
        Fp::new(17936155181893467294),
        Fp::new(1833939650657097992),
        Fp::new(14310984655970610026),
        Fp::new(4701042357351086687),
        Fp::new(1226379890265418475),
        Fp::new(2550212856624409740),
        Fp::new(5670703442709406167),
        Fp::new(3281485106506301394),
        Fp::new(9804247840970323440),
        Fp::new(7778523590474814059),
        Fp::new(7154630063229321501),
        Fp::new(17790326505487126055),
        Fp::new(3160574440608126866),
        Fp::new(7292349907185131376),
        Fp::new(1916491575080831825),
        Fp::new(11523142515674812675),
        Fp::new(2162357063341827157),
        Fp::new(6650415936886875699),
        Fp::new(11522955632464608509),
        Fp::new(16740856792338897018),
        Fp::new(16987840393715133187),
        Fp::new(14499296811525152023),
        Fp::new(118549270069446537),
        Fp::new(3041471724857448013),
        Fp::new(3827228106225598612),
        Fp::new(2081369067662751050),
        Fp::new(15406142490454329462),
        Fp::new(8943531526276617760),
        Fp::new(3545513411057560337),
        Fp::new(11433277564645295966),
        Fp::new(9558995950666358829),
        Fp::new(7443251815414752292),
        Fp::new(12335092608217610725),
        Fp::new(184304165023253232),
        Fp::new(11596940249585433199),
        Fp::new(18170668175083122019),
        Fp::new(8318891703682569182),
        Fp::new(4387895409295967519),
        Fp::new(14599228871586336059),
        Fp::new(2861651216488619239),
        Fp::new(567601091253927304),
        Fp::new(10135289435539766316),
        Fp::new(14905738261734377063),
        Fp::new(3345637344934149303),
        Fp::new(3159874422865401171),
        Fp::new(1134458872778032479),
        Fp::new(4102035717681749376),
        Fp::new(14030271225872148070),
        Fp::new(10312336662487337312),
        Fp::new(12938229830489392977),
        Fp::new(17758804398255988457),
        Fp::new(15482323580054918356),
        Fp::new(1010277923244261213),
        Fp::new(12904552397519353856),
        Fp::new(5073478003078459047),
        Fp::new(11514678194579805863),
        Fp::new(4419017610446058921),
        Fp::new(2916054498252226520),
        Fp::new(9880379926449218161),
        Fp::new(15314650755395914465),
        Fp::new(8335514387550394159),
        Fp::new(8955267746483690029),
        Fp::new(16353914237438359160),
        Fp::new(4173425891602463552),
        Fp::new(14892581052359168234),
        Fp::new(17561678290843148035),
        Fp::new(7292975356887551984),
        Fp::new(18039512759118984712),
        Fp::new(5411253583520971237),
        Fp::new(9848042270158364544),
        Fp::new(809689769037458603),
        Fp::new(5884047526712050760),
        Fp::new(12956871945669043745),
        Fp::new(14265127496637532237),
        Fp::new(6211568220597222123),
        Fp::new(678544061771515015),
        Fp::new(16295989318674734123),
        Fp::new(11782767968925152203),
        Fp::new(1359397660819991739),
        Fp::new(16148400912425385689),
        Fp::new(14440017265059055146),
        Fp::new(1634272668217219807),
        Fp::new(16290589064070324125),
        Fp::new(5311838222680798126),
        Fp::new(15044064140936894715),
        Fp::new(15775025788428030421),
        Fp::new(12586374713559327349),
        Fp::new(8118943473454062014),
        Fp::new(13223746794660766349),
        Fp::new(13059674280609257192),
        Fp::new(16605443174349648289),
        Fp::new(13586971219878687822),
        Fp::new(16337009014471658360),
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
