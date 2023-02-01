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
use super::GriffinHasher;
use super::{apply_permutation, DIGEST_SIZE, RATE_WIDTH, STATE_WIDTH};
use crate::error::SerializationError;
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

impl GriffinHash {
    /// Serializes the current state to an array of bytes
    pub fn to_bytes(&self) -> [u8; 72] {
        let mut res = [0u8; 72];
        assert_eq!(res.len(), STATE_WIDTH * 8 + 8);

        for (index, elem) in self.state.iter().enumerate() {
            res[index * 8..index * 8 + 8].copy_from_slice(&elem.to_bytes());
        }
        res[64..72].copy_from_slice(&(self.idx as u64).to_le_bytes());

        res
    }

    /// Returns a GriffinHash from an array of bytes
    pub fn from_bytes(bytes: &[u8; 72]) -> Result<Self, SerializationError> {
        let mut state = [Fp::zero(); STATE_WIDTH];
        let mut array = [0u8; 8];
        for index in 0..STATE_WIDTH {
            array.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
            let value = Fp::from_bytes(&array);
            state[index] = match value.is_some().into() {
                true => value.unwrap(),
                false => return Err(SerializationError::InvalidFieldElement),
            };
        }

        array.copy_from_slice(&bytes[64..72]);
        let idx = u64::from_le_bytes(array) as usize;

        Ok(Self { state, idx })
    }
}

impl Hasher<Fp> for GriffinHash {
    type Digest = GriffinDigest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // compute the number of elements required to represent the string; we will be processing
        // the string in 7-byte chunks, thus the number of elements will be equal to the number
        // of such chunks (including a potential partial chunk at the end).
        let num_elements = if bytes.len() % 7 == 0 {
            bytes.len() / 7
        } else {
            bytes.len() / 7 + 1
        };

        // initialize state to all zeros, except for the first element of the capacity part, which
        // is set to 1 conditionally on the input length. this is done so that adding zero elements
        // at the end of the list always results in a different hash.
        let mut state = [Fp::zero(); STATE_WIDTH];
        if bytes.len() % 7 != 0 {
            state[RATE_WIDTH] = Fp::one();
        }

        // break the string into 7-byte chunks, convert each chunk into a field element, and
        // absorb the element into the rate portion of the state. we use 7-byte chunks because
        // every 7-byte chunk is guaranteed to map to some field element.
        let mut i = 0;
        let mut num_hashed = 0;
        let mut buf = [0u8; 8];
        for chunk in bytes.chunks(7) {
            if num_hashed + i < num_elements - 1 {
                buf[..7].copy_from_slice(chunk);
            } else {
                // if we are dealing with the last chunk, it may be smaller than 7 bytes long, so
                // we need to handle it slightly differently. we also append a byte with value 1
                // to the end of the string; this pads the string in such a way that adding
                // trailing zeros results in different hash
                let chunk_len = chunk.len();
                buf = [0u8; 8];
                buf[..chunk_len].copy_from_slice(chunk);
                buf[chunk_len] = 1;
            }

            // convert the bytes into a field element and absorb it into the rate portion of the
            // state; if the rate is filled up, apply the Griffin permutation and start absorbing
            // again from zero index.
            state[i] += Fp::new(u64::from_le_bytes(buf));
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
                num_hashed += RATE_WIDTH;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the Griffin permutation.
        // we don't need to apply any extra padding because we injected total number of elements
        // in the input list into the capacity portion of the state during initialization.
        if i > 0 {
            apply_permutation(&mut state);
        }

        // return the first DIGEST_SIZE elements of the state as hash result
        GriffinDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn hash_field(bytes: &[Fp]) -> Self::Digest {
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

impl GriffinHasher<Fp> for GriffinHash {
    /// Initializes a new instance of the permutation.
    fn new() -> Self {
        Self::default()
    }

    /// Absorbs a sequence of bytes.
    fn absorb(&mut self, input: &[u8]) {
        // compute the number of elements required to represent the string; we will be processing
        // the string in 7-byte chunks, thus the number of elements will be equal to the number
        // of such chunks (including a potential partial chunk at the end).
        let num_elements = if input.len() % 7 == 0 {
            input.len() / 7
        } else {
            input.len() / 7 + 1
        };

        // break the string into 7-byte chunks, convert each chunk into a field element, and
        // absorb the element into the rate portion of the state. we use 7-byte chunks because
        // every 7-byte chunk is guaranteed to map to some field element.
        let mut num_hashed = 0;
        let mut buf = [0u8; 8];
        for chunk in input.chunks(7) {
            if num_hashed + self.idx < num_elements - 1 {
                buf[..7].copy_from_slice(chunk);
            } else {
                // if we are dealing with the last chunk, it may be smaller than 7 bytes long, so
                // we need to handle it slightly differently. we also append a byte with value 1
                // to the end of the string; this pads the string in such a way that adding
                // trailing zeros results in different hash

                // Compatibility with the binary hash() is not possible because this would require
                // knowing the total input sequence length at initialization, to write in the capacity
                // registers. Hence, we prevent length-extension attacks on every absorbed chunk
                let chunk_len = chunk.len();
                buf = [0u8; 8];
                buf[..chunk_len].copy_from_slice(chunk);
                buf[chunk_len] = 1;
            }

            // convert the bytes into a field element and absorb it into the rate portion of the
            // state; if the rate is filled up, apply the Griffin permutation and start absorbing
            // again from zero index.
            self.state[self.idx] += Fp::new(u64::from_le_bytes(buf));
            self.idx += 1;
            if self.idx % RATE_WIDTH == 0 {
                apply_permutation(&mut self.state);
                self.idx = 0;
                num_hashed += RATE_WIDTH;
            }
        }
    }

    /// Absorbs a sequence of field elements.
    fn absorb_field(&mut self, input: &[Fp]) {
        for &element in input {
            self.state[self.idx] += element;
            self.idx += 1;
            if self.idx % RATE_WIDTH == 0 {
                apply_permutation(&mut self.state);
                self.idx = 0;
            }
        }
    }

    /// Returns hash of the data absorbed into the hasher.
    fn finalize(&mut self) -> Self::Digest {
        if self.idx > 0 {
            self.state[self.idx] += Fp::one();
            self.idx += 1;

            while self.idx % RATE_WIDTH != 0 {
                self.state[self.idx] += Fp::zero();
                self.idx += 1;
            }

            apply_permutation(&mut self.state);
            self.idx = 0;
        }

        GriffinDigest::new(self.state[..DIGEST_SIZE].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

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
            assert_eq!(expected, GriffinHash::hash_field(input).to_elements());
        }
    }

    #[test]
    fn test_sequential_hashing() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let mut data = [Fp::zero(); 160];
            for e in data.iter_mut() {
                *e = Fp::random(&mut rng);
            }

            let mut hasher = GriffinHash::new();
            for chunk in data.chunks(10) {
                hasher.absorb_field(chunk);
            }

            assert_eq!(hasher.finalize(), GriffinHash::hash_field(&data));
        }
    }

    #[test]
    fn test_serialization() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let mut data = [Fp::zero(); DIGEST_SIZE];
            for e in data.iter_mut() {
                *e = Fp::random(&mut rng);
            }

            let mut hasher = GriffinHash::new();
            hasher.absorb_field(&data);

            let bytes = hasher.to_bytes();

            assert_eq!(hasher, GriffinHash::from_bytes(&bytes).unwrap());
        }

        // Test invalid encoding
        let mut data = [Fp::zero(); DIGEST_SIZE];
        for e in data.iter_mut() {
            *e = Fp::random(&mut rng);
        }

        let mut hasher = GriffinHash::new();
        hasher.absorb_field(&data);

        let bytes = [255u8; 72];

        assert!(GriffinHash::from_bytes(&bytes).is_err());
    }
}