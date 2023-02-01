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
use super::RescuePrimeHasher;
use super::{apply_permutation, DIGEST_SIZE, RATE_WIDTH, STATE_WIDTH};
use crate::error::SerializationError;
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

impl RescueHash {
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

    /// Returns a RescueHash from an array of bytes
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

impl Hasher<Fp> for RescueHash {
    type Digest = RescueDigest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // compute the number of elements required to represent the string; we will be processing
        // the string in 7-byte chunks, thus the number of elements will be equal to the number
        // of such chunks (including a potential partial chunk at the end).
        let num_elements = if bytes.len() % 7 == 0 {
            bytes.len() / 7
        } else {
            bytes.len() / 7 + 1
        };

        // initialize state to all zeros, except for the last element of the capacity part, which
        // is set to the number of elements to be hashed. this is done so that adding zero elements
        // at the end of the list always results in a different hash.
        let mut state = [Fp::zero(); STATE_WIDTH];
        state[STATE_WIDTH - 1] = Fp::new(num_elements as u64);

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
            // state; if the rate is filled up, apply the Rescue permutation and start absorbing
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
        // the number of elements is not a multiple of RATE_WIDTH), apply the Rescue permutation.
        // we don't need to apply any extra padding because we injected total number of elements
        // in the input list into the capacity portion of the state during initialization.
        if i > 0 {
            apply_permutation(&mut state);
        }

        // return the first DIGEST_SIZE elements of the state as hash result
        RescueDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn hash_field(bytes: &[Fp]) -> Self::Digest {
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

impl RescuePrimeHasher<Fp> for RescueHash {
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
            // state; if the rate is filled up, apply the Rescue permutation and start absorbing
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
        // Apply padding specification from https://eprint.iacr.org/2020/1143.pdf, Algorithm 2
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

        RescueDigest::new(self.state[..DIGEST_SIZE].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

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
            let mut hasher = RescueHash::new();
            hasher.absorb_field(input);

            assert_eq!(expected, hasher.finalize().to_elements());
            assert_eq!(expected, RescueHash::hash_field(input).to_elements());
        }
    }

    #[test]
    fn test_sequential_hashing() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let mut data = [Fp::zero(); 120];
            for e in data.iter_mut() {
                *e = Fp::random(&mut rng);
            }

            let mut hasher = RescueHash::new();
            for chunk in data.chunks(10) {
                hasher.absorb_field(chunk);
            }

            assert_eq!(hasher.finalize(), RescueHash::hash_field(&data));
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

            let mut hasher = RescueHash::new();
            hasher.absorb_field(&data);

            let bytes = hasher.to_bytes();

            assert_eq!(hasher, RescueHash::from_bytes(&bytes).unwrap());
        }

        // Test invalid encoding
        let mut data = [Fp::zero(); DIGEST_SIZE];
        for e in data.iter_mut() {
            *e = Fp::random(&mut rng);
        }

        let mut hasher = RescueHash::new();
        hasher.absorb_field(&data);

        let bytes = [255u8; 72];

        assert!(RescueHash::from_bytes(&bytes).is_err());
    }
}
