// Copyright (c) 2021-2022 Toposware, Inc.
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
    pub fn to_bytes(&self) -> [u8; 104] {
        let mut res = [0u8; 104];
        assert_eq!(res.len(), STATE_WIDTH * 8 + 8);

        for (index, elem) in self.state.iter().enumerate() {
            res[index * 8..index * 8 + 8].copy_from_slice(&elem.to_bytes());
        }
        res[96..104].copy_from_slice(&(self.idx as u64).to_le_bytes());

        res
    }

    /// Returns a RescueHash from an array of bytes
    pub fn from_bytes(bytes: &[u8; 104]) -> Result<Self, SerializationError> {
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

        array.copy_from_slice(&bytes[96..104]);
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
        state[..DIGEST_SIZE].copy_from_slice(values[0].as_elements());
        state[DIGEST_SIZE..RATE_WIDTH].copy_from_slice(values[1].as_elements());
        apply_permutation(&mut state);

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
                Fp::new(6901193510266584396),
                Fp::new(11128900379036895339),
                Fp::new(13213579100026630082),
                Fp::new(15391926583391034115),
                Fp::new(5447509840651589213),
                Fp::new(1520995725425242095),
                Fp::new(17093575254904882474),
                Fp::new(17961708977301084862),
            ],
            [
                Fp::new(12054530659531339625),
                Fp::new(15317335722079052361),
                Fp::new(1984459072705852955),
                Fp::new(11856524579493381847),
                Fp::new(6559312467615199656),
                Fp::new(14336968646180522392),
                Fp::new(14192671717145625613),
                Fp::new(11260159092533647349),
            ],
            [
                Fp::new(10412515509097980411),
                Fp::new(12722889595005331676),
                Fp::new(4219450234669481952),
                Fp::new(11163576234532866331),
                Fp::new(13563563603669262984),
                Fp::new(8440095100855451781),
                Fp::new(14754101614955165009),
                Fp::new(12222483440306699644),
            ],
            [
                Fp::new(11727396019189827811),
                Fp::new(2135274820919406570),
                Fp::new(14386498183202104819),
                Fp::new(11403598566275142336),
                Fp::new(18184009512828014803),
                Fp::new(9147643160041196657),
                Fp::new(17268902596129982091),
                Fp::new(8791187538207479838),
            ],
            [
                Fp::new(1212247392102526324),
                Fp::new(8365260885893716876),
                Fp::new(14031477841214367770),
                Fp::new(11314940593907920526),
                Fp::new(3030331368470810361),
                Fp::new(14374747233275556453),
                Fp::new(12652244313709497312),
                Fp::new(157151945167908123),
            ],
            [
                Fp::new(8079785124245849604),
                Fp::new(17948490874532416147),
                Fp::new(11626558578930760634),
                Fp::new(13520438176347873602),
                Fp::new(3990105819352401287),
                Fp::new(6569973125161671098),
                Fp::new(4209337259159854635),
                Fp::new(11577053759934507857),
            ],
            [
                Fp::new(1255500616033723278),
                Fp::new(4508041192890198900),
                Fp::new(2261208286016596373),
                Fp::new(14980787052236183596),
                Fp::new(17825370834820266719),
                Fp::new(14192467126277950600),
                Fp::new(5770707447878175748),
                Fp::new(2397396294780245329),
            ],
            [
                Fp::new(5304581631049996791),
                Fp::new(3363973626156060606),
                Fp::new(18070666534472402361),
                Fp::new(14611764180518318891),
                Fp::new(3455847088066227292),
                Fp::new(15622544447622888791),
                Fp::new(4613941394201239982),
                Fp::new(1669704328224028946),
            ],
            [
                Fp::new(14561472593774281871),
                Fp::new(17508482171005284137),
                Fp::new(13906165849131180933),
                Fp::new(6045018631631498757),
                Fp::new(2380862931333578744),
                Fp::new(6720908023754338693),
                Fp::new(13210887390249755924),
                Fp::new(13600016253970808442),
            ],
            [
                Fp::new(251540717373339786),
                Fp::new(16264775296569355656),
                Fp::new(15365038663612262046),
                Fp::new(9367947686783287059),
                Fp::new(9031081423427454162),
                Fp::new(13700499765176012619),
                Fp::new(15923886032917146831),
                Fp::new(7672787664490715429),
            ],
        ];

        // Generated from https://github.com/KULeuven-COSIC/Marvellous
        let output_data = [
            [
                Fp::new(1240173021739825258),
                Fp::new(9047404359086439889),
                Fp::new(13946832583192193956),
                Fp::new(10670876233672665509),
            ],
            [
                Fp::new(15256504301092167891),
                Fp::new(4232464537090237781),
                Fp::new(11630886206283039283),
                Fp::new(17082842315565495575),
            ],
            [
                Fp::new(12203812172435500204),
                Fp::new(15376848320172068410),
                Fp::new(11125891857379823636),
                Fp::new(4921022385148443609),
            ],
            [
                Fp::new(13194924350723779031),
                Fp::new(13315947935666707356),
                Fp::new(14573240265130310614),
                Fp::new(14512967397866915765),
            ],
            [
                Fp::new(6347142452506890479),
                Fp::new(14942480234078019926),
                Fp::new(1701196680103645520),
                Fp::new(17725808483374275242),
            ],
            [
                Fp::new(17072439836571516345),
                Fp::new(7578994671326089233),
                Fp::new(7715554848016729429),
                Fp::new(3714073905172709565),
            ],
            [
                Fp::new(16135598057438024949),
                Fp::new(12277543443284715999),
                Fp::new(5383504497150239811),
                Fp::new(11143713063562574228),
            ],
            [
                Fp::new(314811332480964883),
                Fp::new(8179333661000625461),
                Fp::new(915004691864055036),
                Fp::new(12767274626172980688),
            ],
            [
                Fp::new(742302430947857655),
                Fp::new(3216969767653766452),
                Fp::new(767683404688120997),
                Fp::new(12248551398097834281),
            ],
            [
                Fp::new(5154366327879564410),
                Fp::new(6142970624575430653),
                Fp::new(8443024227462860469),
                Fp::new(5270824100247548317),
            ],
            [
                Fp::new(11926724954470794387),
                Fp::new(8329364317908643469),
                Fp::new(17912555411449961362),
                Fp::new(6310571155941761664),
            ],
            [
                Fp::new(13240348269964623989),
                Fp::new(5729501884039990563),
                Fp::new(15804162421858776904),
                Fp::new(13501924956684857964),
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
            let mut data = [Fp::zero(); 160];
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

        let bytes = [255u8; 104];

        assert!(RescueHash::from_bytes(&bytes).is_err());
    }
}
