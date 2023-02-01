// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Hasher trait implementation for Anemoi

use core::convert::TryInto;

use super::digest::AnemoiDigest;
use super::{apply_permutation, DIGEST_SIZE, NUM_COLUMNS, RATE_WIDTH, STATE_WIDTH};
use crate::traits::Hasher;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use cheetah::Fp;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// A Anemoi Hash over Fp
pub struct AnemoiHash {
    state: [Fp; STATE_WIDTH],
    idx: usize,
}

impl Default for AnemoiHash {
    fn default() -> Self {
        Self {
            state: [Fp::zero(); STATE_WIDTH],
            idx: 0,
        }
    }
}

impl Hasher<Fp> for AnemoiHash {
    type Digest = AnemoiDigest;

    fn hash(bytes: &[Fp]) -> Self::Digest {
        // initialize state to all zeros.
        let mut state = [Fp::zero(); STATE_WIDTH];

        let sigma = if bytes.len() % RATE_WIDTH == 0 {
            Fp::one()
        } else {
            Fp::zero()
        };

        let mut i = 0;
        for &element in bytes.iter() {
            state[i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
            }
        }

        // If the message length is not a multiple of RATE_WIDTH, we append 1 to the rate cell
        // next to the one where we previously appended the last message element. This is
        // guaranted to be in the rate registers (i.e. to not require an extra permutation before
        // adding this constant) if sigma is equal to zero.
        if sigma.is_zero().into() {
            state[i] += Fp::one();
            apply_permutation(&mut state);
        }

        // We then add sigma to the last capacity register of the capacity.
        state[STATE_WIDTH - 1] += sigma;

        AnemoiDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    // This merge function uses the compression approach of Anemoi-Jive
    // to save one Anemoi permutation call , which would be necessary if
    // using the regular Anemoi-Sponge to absorb two digests, both of
    // size RATE_WIDTH.
    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = [Fp::zero(); STATE_WIDTH];
        let digest1 = values[0].as_elements();
        let digest2 = values[1].as_elements();
        state[..RATE_WIDTH].copy_from_slice(digest1);
        state[RATE_WIDTH..STATE_WIDTH].copy_from_slice(digest2);
        apply_permutation(&mut state);

        let mut result = [Fp::zero(); DIGEST_SIZE];
        for (i, r) in result.iter_mut().enumerate() {
            *r = digest1[i] + digest2[i] + state[i] + state[i + NUM_COLUMNS];
        }

        AnemoiDigest::new(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anemoi_hash() {
        // Hardcoded input / output list generated from the
        // Sagemath code at https://github.com/Nashtare/anemoi-hash/

        let input_data = [
            vec![Fp::zero(); 8],
            vec![Fp::one(); 8],
            vec![
                Fp::zero(),
                Fp::zero(),
                Fp::zero(),
                Fp::zero(),
                Fp::one(),
                Fp::one(),
                Fp::one(),
                Fp::one(),
            ],
            vec![
                Fp::one(),
                Fp::one(),
                Fp::one(),
                Fp::one(),
                Fp::zero(),
                Fp::zero(),
                Fp::zero(),
                Fp::zero(),
            ],
            vec![Fp::new(17034304680378990593)],
            vec![Fp::new(14717522243836148645), Fp::new(13083744320516212099)],
            vec![
                Fp::new(12636374470493764585),
                Fp::new(4633685103624134705),
                Fp::new(3387113220078373436),
            ],
            vec![
                Fp::new(8456646190515084682),
                Fp::new(13422660296625058046),
                Fp::new(6412264356237719015),
                Fp::new(15681324668660747245),
            ],
            vec![
                Fp::new(5024098825481674854),
                Fp::new(17074804226935063103),
                Fp::new(12706716815026291874),
                Fp::new(15111404609115389377),
                Fp::new(14660803971611056841),
            ],
            vec![
                Fp::new(12593193490016384806),
                Fp::new(18163695353480745896),
                Fp::new(12379842404544411425),
                Fp::new(15341182951106044393),
                Fp::new(1499922380158571885),
                Fp::new(4387632416457430195),
            ],
        ];

        let output_data = [
            [
                Fp::new(163801914873424873),
                Fp::new(1975920130069291731),
                Fp::new(11347519605622270163),
                Fp::new(13645969218783075933),
            ],
            [
                Fp::new(10146598142737807481),
                Fp::new(16567096201507333296),
                Fp::new(17955106716319642741),
                Fp::new(4860486773238898208),
            ],
            [
                Fp::new(6111781501637081646),
                Fp::new(10187415424684290095),
                Fp::new(17663585034052564413),
                Fp::new(1533771651848622457),
            ],
            [
                Fp::new(6882943066109610085),
                Fp::new(18116611745108827517),
                Fp::new(10320885853741934988),
                Fp::new(851003075264447500),
            ],
            [
                Fp::new(9937678481006433665),
                Fp::new(5613531991639406668),
                Fp::new(826203708134430950),
                Fp::new(5856376835295707176),
            ],
            [
                Fp::new(12354948106612827967),
                Fp::new(18225731063279096760),
                Fp::new(12692549507758853073),
                Fp::new(5857129691129105835),
            ],
            [
                Fp::new(17178281612961548790),
                Fp::new(15592307425962170877),
                Fp::new(3291082425520566106),
                Fp::new(1457588681846648616),
            ],
            [
                Fp::new(3831087655484288576),
                Fp::new(1529151277776990392),
                Fp::new(18237347415792447921),
                Fp::new(2518543518700876920),
            ],
            [
                Fp::new(39132530386866452),
                Fp::new(12435901606157783280),
                Fp::new(16259807811311764920),
                Fp::new(13912323646801342253),
            ],
            [
                Fp::new(12397702082065942083),
                Fp::new(15528997894970156290),
                Fp::new(7340685217165164207),
                Fp::new(12732717666166972168),
            ],
        ];

        for (input, expected) in input_data.iter().zip(output_data) {
            assert_eq!(expected, AnemoiHash::hash(input).to_elements());
        }
    }
}
