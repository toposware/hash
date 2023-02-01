// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Hasher trait implementation for Griffin

use core::convert::TryInto;

use super::digest::GriffinDigest;
use super::{apply_permutation, DIGEST_SIZE, RATE_WIDTH, STATE_WIDTH};
use crate::traits::Hasher;

use cheetah::Fp;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// A Griffin Hash over Fp
pub struct GriffinHash {
    state: [Fp; STATE_WIDTH],
    idx: usize,
}

impl Default for GriffinHash {
    fn default() -> Self {
        Self {
            state: [Fp::zero(); STATE_WIDTH],
            idx: 0,
        }
    }
}

impl Hasher<Fp> for GriffinHash {
    type Digest = GriffinDigest;

    fn hash(bytes: &[Fp]) -> Self::Digest {
        // initialize state to all zeros, except for the first element of the capacity part, which
        // is set to 1 conditionally on the input length. this is done so that adding zero elements
        // at the end of the list always results in a different hash.
        let mut state = [Fp::zero(); STATE_WIDTH];
        if bytes.len() % RATE_WIDTH != 0 {
            state[RATE_WIDTH] = Fp::one();
        }

        let mut i = 0;
        for &element in bytes.iter() {
            state[i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
            }
        }

        if i > 0 {
            state[i] += Fp::one();
            apply_permutation(&mut state);
        }

        GriffinDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
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

        GriffinDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_griffin_hash() {
        // Hardcoded input / output list generated from the
        // Sagemath code at https://github.com/Nashtare/griffin-hash/tree/vanilla

        let input_data = [
            [Fp::zero(); 8],
            [Fp::one(); 8],
            [
                Fp::new(2510332138772683030),
                Fp::new(4149518646905375368),
                Fp::new(1823267482195900486),
                Fp::new(15094072369316226406),
                Fp::new(14733663596186751286),
                Fp::new(10731075739676888684),
                Fp::new(11654099692908959328),
                Fp::new(6446144346839832201),
            ],
            [
                Fp::new(7390477777229681770),
                Fp::new(5279943844209426765),
                Fp::new(13649541140802065737),
                Fp::new(1898713590695919847),
                Fp::new(18017762047681407283),
                Fp::new(10920063131926457282),
                Fp::new(10358748483883915701),
                Fp::new(14878133478123446934),
            ],
            [
                Fp::new(13632197808257598012),
                Fp::new(13451069352046316993),
                Fp::new(13619682124657548202),
                Fp::new(14723441883064102525),
                Fp::new(1139014445451681882),
                Fp::new(9578952098066825768),
                Fp::new(17256762572429566825),
                Fp::new(5358567478155041882),
            ],
            [
                Fp::new(12717178657788591092),
                Fp::new(2595051118547632521),
                Fp::new(9707143557661613313),
                Fp::new(2931830948356888275),
                Fp::new(16310345872365494301),
                Fp::new(6847926980825396987),
                Fp::new(12802040900462007036),
                Fp::new(9661868549054691621),
            ],
            [
                Fp::new(13313127370857946868),
                Fp::new(15756171029022485997),
                Fp::new(2824180514814869634),
                Fp::new(7440533223558820164),
                Fp::new(14667760116607791512),
                Fp::new(13066539746577461076),
                Fp::new(12102203229855053980),
                Fp::new(471503781898043118),
            ],
            [
                Fp::new(190736727476169262),
                Fp::new(195974481052828714),
                Fp::new(8119593719922089925),
                Fp::new(10769917037219797152),
                Fp::new(11874878280587616125),
                Fp::new(12800560275751247392),
                Fp::new(14407033076521383924),
                Fp::new(12444092855514688737),
            ],
            [
                Fp::new(3178701265640302906),
                Fp::new(4463529421114540456),
                Fp::new(14458042151951923858),
                Fp::new(5872791376566645631),
                Fp::new(10819264142758393761),
                Fp::new(13171141544785796286),
                Fp::new(10857638519890544753),
                Fp::new(1465505821245525727),
            ],
            [
                Fp::new(546169214346871646),
                Fp::new(4956942587682404550),
                Fp::new(15538968694093212423),
                Fp::new(4828344261693981368),
                Fp::new(2786005378940114649),
                Fp::new(2337429148680081245),
                Fp::new(17623419611341140290),
                Fp::new(16611733645745088838),
            ],
            [
                Fp::new(15277150056649369655),
                Fp::new(14188660724585713308),
                Fp::new(12289919700136990366),
                Fp::new(13224692183130701731),
                Fp::new(16820023449827445520),
                Fp::new(6848305810606932878),
                Fp::new(5646064461712912544),
                Fp::new(16112843324800938839),
            ],
            [
                Fp::new(11566696823965485178),
                Fp::new(16971066076784638863),
                Fp::new(3039823736517801502),
                Fp::new(17017071501428580428),
                Fp::new(5377308546605007107),
                Fp::new(13803949600501203931),
                Fp::new(93523036508513611),
                Fp::new(16535958346598345079),
            ],
        ];

        // Generated from https://github.com/Nashtare/griffin-hash/tree/vanilla
        let output_data = [
            [
                Fp::new(9460700025515717926),
                Fp::new(7038153142753916782),
                Fp::new(16981426932070807662),
                Fp::new(6397236168285558197),
            ],
            [
                Fp::new(10310688758698891537),
                Fp::new(13868469464239224107),
                Fp::new(16999148167516098413),
                Fp::new(3339091193759434036),
            ],
            [
                Fp::new(9908831366460994042),
                Fp::new(13704561069053898118),
                Fp::new(6962653801791137528),
                Fp::new(13810306413359646436),
            ],
            [
                Fp::new(14436935945620058552),
                Fp::new(15422007355571220354),
                Fp::new(18026090297881054875),
                Fp::new(3483685760486935268),
            ],
            [
                Fp::new(3546376763135359504),
                Fp::new(17061092015038688212),
                Fp::new(2608056578773763341),
                Fp::new(15603360739102087893),
            ],
            [
                Fp::new(6580628385468574084),
                Fp::new(3852696640052051600),
                Fp::new(7643480721938071453),
                Fp::new(1441053012060688141),
            ],
            [
                Fp::new(13715673450605909969),
                Fp::new(3360059965870337524),
                Fp::new(18314892960029671543),
                Fp::new(2269675939609942883),
            ],
            [
                Fp::new(17605497520765638857),
                Fp::new(4178582088890869209),
                Fp::new(4227275774349455564),
                Fp::new(12423313808039857815),
            ],
            [
                Fp::new(15416102573339492304),
                Fp::new(10171536346814741060),
                Fp::new(13728219902305131326),
                Fp::new(13969183195497947914),
            ],
            [
                Fp::new(6146940920476183302),
                Fp::new(1041241518359659399),
                Fp::new(2947713206713221278),
                Fp::new(9609879150744354457),
            ],
            [
                Fp::new(13269111110215355645),
                Fp::new(3861463649313444888),
                Fp::new(17380428413698903507),
                Fp::new(17103744698941994418),
            ],
            [
                Fp::new(10377878869936932769),
                Fp::new(6918100690615411221),
                Fp::new(12419648883711830271),
                Fp::new(7506836827576189701),
            ],
        ];

        for (input, expected) in input_data.iter().zip(output_data) {
            assert_eq!(expected, GriffinHash::hash(input).to_elements());
        }
    }
}
