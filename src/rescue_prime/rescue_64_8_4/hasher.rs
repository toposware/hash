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
        let digest1 = values[0].as_elements();
        let digest2 = values[1].as_elements();
        // Uses Jive compression to fill the whole state and perform a single permutation
        state[..RATE_WIDTH].copy_from_slice(digest1);
        state[RATE_WIDTH..STATE_WIDTH].copy_from_slice(digest2);
        apply_permutation(&mut state);

        let mut result = [Fp::zero(); DIGEST_SIZE];
        for (i, r) in result.iter_mut().enumerate() {
            *r = digest1[i] + digest2[i] + state[i] + state[i + STATE_WIDTH / 2];
        }

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
                Fp::new(2434186379914510897),
                Fp::new(5246955456544205025),
                Fp::new(6389144627169380549),
                Fp::new(12797518479118847287),
                Fp::new(6780537105603247507),
                Fp::new(7463236985176960461),
                Fp::new(11150690039618633810),
                Fp::new(16408515287400785328),
            ],
            [
                Fp::new(2063470740780987876),
                Fp::new(15979531037654382502),
                Fp::new(7938863172860053558),
                Fp::new(12781539140410727521),
                Fp::new(367580324415377698),
                Fp::new(11425096625575462496),
                Fp::new(1828048291809209162),
                Fp::new(6326364615236129646),
            ],
            [
                Fp::new(340684484350794854),
                Fp::new(10519566338355245407),
                Fp::new(17602633331336175470),
                Fp::new(15946716446662536536),
                Fp::new(12689618799772881285),
                Fp::new(14453825849735393824),
                Fp::new(7874323729428474524),
                Fp::new(6073338743257451305),
            ],
            [
                Fp::new(174342169376276206),
                Fp::new(5158351784964951808),
                Fp::new(874087699483774003),
                Fp::new(1990589532511411858),
                Fp::new(7202931906605024533),
                Fp::new(2486404590755011906),
                Fp::new(12994163076456894044),
                Fp::new(1059432242777748904),
            ],
            [
                Fp::new(14349585911485427758),
                Fp::new(12778390717486300985),
                Fp::new(7884327698783858032),
                Fp::new(15842733290297774571),
                Fp::new(15798822153644426815),
                Fp::new(3480311725675760076),
                Fp::new(5298925139140640791),
                Fp::new(5954759136603994891),
            ],
            [
                Fp::new(1170327656060017140),
                Fp::new(7240761483496524575),
                Fp::new(2237735472637515316),
                Fp::new(13595978478581213206),
                Fp::new(16772585398563366408),
                Fp::new(11240120236698908203),
                Fp::new(18003416411369351062),
                Fp::new(3345123843895522218),
            ],
            [
                Fp::new(6545159187784369640),
                Fp::new(17773203980353600112),
                Fp::new(11194199939663523419),
                Fp::new(11062632088050417388),
                Fp::new(6891099374711756634),
                Fp::new(3387259595967126876),
                Fp::new(11208886964090182503),
                Fp::new(9075700008374803043),
            ],
            [
                Fp::new(12434344232824855777),
                Fp::new(11983076062735788292),
                Fp::new(14312653804290082378),
                Fp::new(826920072288117137),
                Fp::new(6947056285003372932),
                Fp::new(12240953988159408739),
                Fp::new(11744335918983994823),
                Fp::new(16710316000338901733),
            ],
            [
                Fp::new(17894941280835586546),
                Fp::new(1839894647541780206),
                Fp::new(15123237584878215927),
                Fp::new(3937722182752290885),
                Fp::new(12738635520453845531),
                Fp::new(14563165815687411738),
                Fp::new(2115867556366432136),
                Fp::new(7533814879066187202),
            ],
            [
                Fp::new(2347631260359526863),
                Fp::new(15778462961919867074),
                Fp::new(3694776677967284839),
                Fp::new(14240106889666386374),
                Fp::new(12219688250420905700),
                Fp::new(15094316512909593866),
                Fp::new(4281720034514716351),
                Fp::new(2616392141689281680),
            ],
        ];

        // Generated from https://github.com/KULeuven-COSIC/Marvellous
        let output_data = [
            [
                Fp::new(14718625328705843065),
                Fp::new(17590266694296889245),
                Fp::new(10710872897056847633),
                Fp::new(3159318215468806765),
            ],
            [
                Fp::new(16500762660685380974),
                Fp::new(797884976122780828),
                Fp::new(5649358182916312713),
                Fp::new(14985207243099757289),
            ],
            [
                Fp::new(4615664097085569179),
                Fp::new(4662234908300368148),
                Fp::new(14255405155940688638),
                Fp::new(5037892409079533778),
            ],
            [
                Fp::new(3507269265597853626),
                Fp::new(292991240830672997),
                Fp::new(3679626200237029824),
                Fp::new(18136878091054641769),
            ],
            [
                Fp::new(13577071073273451164),
                Fp::new(11866993303445349078),
                Fp::new(2909027013939062571),
                Fp::new(8760337506864785878),
            ],
            [
                Fp::new(11644288219502440547),
                Fp::new(6084816989261543771),
                Fp::new(12706117115874136801),
                Fp::new(7695851106989088081),
            ],
            [
                Fp::new(5706317153597320396),
                Fp::new(927015110787343904),
                Fp::new(1202328441100444579),
                Fp::new(15265789387912833855),
            ],
            [
                Fp::new(7180160177901338900),
                Fp::new(1910274244169561244),
                Fp::new(12105732498240765577),
                Fp::new(14663677358275851769),
            ],
            [
                Fp::new(1984155149456289154),
                Fp::new(8445846960352702353),
                Fp::new(13781222931834769723),
                Fp::new(4603936348540105550),
            ],
            [
                Fp::new(12022462518458220840),
                Fp::new(15236523747340896253),
                Fp::new(9051105680854615995),
                Fp::new(13321057017788658109),
            ],
            [
                Fp::new(11512954709067359873),
                Fp::new(8841254070643856407),
                Fp::new(1095235585335202160),
                Fp::new(18423553725217064591),
            ],
            [
                Fp::new(1860847324323242507),
                Fp::new(15597023587848369037),
                Fp::new(8676704488983008626),
                Fp::new(16930907085168216749),
            ],
        ];

        for (input, expected) in input_data.iter().zip(output_data) {
            assert_eq!(expected, RescueHash::hash(input).to_elements());
        }
    }
}
