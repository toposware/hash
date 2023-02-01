// Copyright (c) 2021-2023 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Hasher trait implementation for Rescue

use core::convert::TryInto;

use super::digest::RescueDigest;
use super::{apply_permutation, DIGEST_SIZE, RATE_WIDTH, STATE_WIDTH};
use crate::traits::Hasher;

use cheetah::Fp;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// A Rescue Hash over Fp
pub struct RescueHash {
    state: [Fp; STATE_WIDTH],
    idx: usize,
}

impl Default for RescueHash {
    fn default() -> Self {
        Self {
            state: [Fp::zero(); STATE_WIDTH],
            idx: 0,
        }
    }
}

impl Hasher<Fp> for RescueHash {
    type Digest = RescueDigest;

    fn hash(bytes: &[Fp]) -> Self::Digest {
        // initialize state to all zeros
        let mut state = [Fp::zero(); STATE_WIDTH];

        let mut i = 0;
        for &element in bytes.iter() {
            state[i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
            }
        }

        // Apply padding specification from https://eprint.iacr.org/2020/1143.pdf, Algorithm 2
        if i > 0 {
            state[i] += Fp::one();
            i += 1;

            while i % RATE_WIDTH != 0 {
                state[i] = Fp::zero();
                i += 1;
            }

            apply_permutation(&mut state);
        }

        RescueDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = [Fp::zero(); STATE_WIDTH];
        state[..DIGEST_SIZE].copy_from_slice(values[0].as_elements());
        state[DIGEST_SIZE..RATE_WIDTH].copy_from_slice(values[1].as_elements());
        apply_permutation(&mut state);

        RescueDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rescue_hash() {
        // Hardcoded input / output list generated from the
        // Sagemath code at https://github.com/KULeuven-COSIC/Marvellous

        let input_data = [
            [Fp::zero(); 8],
            [Fp::one(); 8],
            [
                Fp::new(7530915893948438626),
                Fp::new(8800061101499087155),
                Fp::new(12743810843683093000),
                Fp::new(4628143886977575438),
                Fp::new(16155374671114756449),
                Fp::new(225681431990641162),
                Fp::new(3305860315173298679),
                Fp::new(12303317461071026747),
            ],
            [
                Fp::new(9232740412975669615),
                Fp::new(9217116013228601478),
                Fp::new(4293830967808188456),
                Fp::new(15456182631886251678),
                Fp::new(3618766818863880191),
                Fp::new(6280935809956460128),
                Fp::new(7166666823015080026),
                Fp::new(15302134487432567685),
            ],
            [
                Fp::new(8976450671476087579),
                Fp::new(5206208508610893389),
                Fp::new(12271224547228316131),
                Fp::new(14562169154073895878),
                Fp::new(18381637277455387460),
                Fp::new(2224570723939504398),
                Fp::new(7905616110921470821),
                Fp::new(15810140845034840589),
            ],
            [
                Fp::new(14703595238443130817),
                Fp::new(12269863200642762253),
                Fp::new(13309074902582409385),
                Fp::new(11451252427570209184),
                Fp::new(13949002048085204773),
                Fp::new(3506016914581130862),
                Fp::new(8294829337045451114),
                Fp::new(14730089488118988067),
            ],
            [
                Fp::new(13727543658444052614),
                Fp::new(3301731079042393535),
                Fp::new(8773684773487387580),
                Fp::new(12457097156282238046),
                Fp::new(4773227697638147630),
                Fp::new(3041578054038681607),
                Fp::new(14910324427389276793),
                Fp::new(17119171213850456798),
            ],
            [
                Fp::new(7051595418337823791),
                Fp::new(11061065355704098278),
                Fp::new(7769052988784367659),
                Fp::new(11464517154732981339),
                Fp::new(11860578015795370951),
                Fp::new(6482118144004227366),
                Fp::new(2643075426059191149),
                Fp::new(10845980447339616669),
            ],
            [
                Fp::new(3739407871605716475),
                Fp::new(9932405777274885080),
                Fp::new(1036973164224876505),
                Fp::new(8847574931823078112),
                Fp::new(16331651222792910346),
                Fp::new(1409516521885489804),
                Fp::new(12498791972854057381),
                Fp::new(13213095980122521460),
            ],
            [
                Fp::new(15948280688979628003),
                Fp::new(4542759336325540548),
                Fp::new(10423869491311504304),
                Fp::new(6116965229813709897),
                Fp::new(9997452706318235316),
                Fp::new(12234278137845288153),
                Fp::new(11331574913163666769),
                Fp::new(6716575775176135507),
            ],
            [
                Fp::new(17343255975828003173),
                Fp::new(6841835512675325978),
                Fp::new(3178096146976164032),
                Fp::new(6827999881416465630),
                Fp::new(408991702186327027),
                Fp::new(13945938860465172083),
                Fp::new(11199243469254684516),
                Fp::new(2364947769764614259),
            ],
            [
                Fp::new(16866739842298834481),
                Fp::new(15804104725181108095),
                Fp::new(16235277953650691713),
                Fp::new(2380130476509117239),
                Fp::new(2486067328955017838),
                Fp::new(114713685744251284),
                Fp::new(16291208580772733813),
                Fp::new(13085537500555952616),
            ],
        ];

        // Generated from https://github.com/KULeuven-COSIC/Marvellous
        let output_data = [
            [
                Fp::new(8957274432841348180),
                Fp::new(3462715397810997323),
                Fp::new(9112765074729698987),
                Fp::new(11355028649842365827),
            ],
            [
                Fp::new(16860573314894026072),
                Fp::new(5223843823279297510),
                Fp::new(17146077934831331816),
                Fp::new(1076129696200382409),
            ],
            [
                Fp::new(385451156385315105),
                Fp::new(11994038392662145018),
                Fp::new(7632024281529462977),
                Fp::new(5317415691698369519),
            ],
            [
                Fp::new(7634219720733306056),
                Fp::new(6889289224278063501),
                Fp::new(3463611688492982199),
                Fp::new(12243541559173475734),
            ],
            [
                Fp::new(12910778150988268406),
                Fp::new(6721677852547751722),
                Fp::new(15338667631621161111),
                Fp::new(3349511616106826986),
            ],
            [
                Fp::new(14074513124259758560),
                Fp::new(10576045581525278514),
                Fp::new(17596596104494687104),
                Fp::new(9631486794090898638),
            ],
            [
                Fp::new(14255128892540666349),
                Fp::new(14035587348265876394),
                Fp::new(3245911794536653629),
                Fp::new(7140385534664095817),
            ],
            [
                Fp::new(14314174965950323374),
                Fp::new(4276965885099153937),
                Fp::new(2275243438436362800),
                Fp::new(7252573281430515362),
            ],
            [
                Fp::new(5209700993096539928),
                Fp::new(6089625723753540745),
                Fp::new(6297390213497306087),
                Fp::new(4509897997873590055),
            ],
            [
                Fp::new(16375031809269366825),
                Fp::new(1975494321099680522),
                Fp::new(16172742695858153202),
                Fp::new(12794730112675404054),
            ],
            [
                Fp::new(3565792055342030874),
                Fp::new(5739572764667266160),
                Fp::new(9803656867053797995),
                Fp::new(14218697028597755720),
            ],
            [
                Fp::new(5167820285577335236),
                Fp::new(9477824282780185416),
                Fp::new(6769847770881182012),
                Fp::new(809373104972971964),
            ],
        ];

        for (input, expected) in input_data.iter().zip(output_data) {
            assert_eq!(expected, RescueHash::hash(input).to_elements());
        }
    }
}
