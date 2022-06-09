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
        state[..DIGEST_SIZE].copy_from_slice(&values[0].as_elements());
        state[DIGEST_SIZE..RATE_WIDTH].copy_from_slice(&values[1].as_elements());
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
                Fp::new(10549796622544520239),
                Fp::new(6835820560903023964),
                Fp::new(8107907236950980777),
                Fp::new(11767100992689091464),
                Fp::new(15380268809656427116),
                Fp::new(2649823800424054377),
                Fp::new(506166418670196758),
                Fp::new(17750386604551827417),
            ],
            [
                Fp::new(18306170753738911459),
                Fp::new(9784919319936395224),
                Fp::new(8544662678680644553),
                Fp::new(16762935495572044280),
                Fp::new(2064960208598065387),
                Fp::new(14516091320834356288),
                Fp::new(1789492685239812268),
                Fp::new(18192689517849927824),
            ],
            [
                Fp::new(277022920045966261),
                Fp::new(7199590003338089407),
                Fp::new(15387898073252386558),
                Fp::new(9815449522604035439),
                Fp::new(577347496162543596),
                Fp::new(13103311305504657950),
                Fp::new(370432008525598671),
                Fp::new(75069842648526388),
            ],
            [
                Fp::new(2000201464842524034),
                Fp::new(9974318451859345002),
                Fp::new(5432740095202333044),
                Fp::new(8175466915171182793),
                Fp::new(9152331808892175447),
                Fp::new(15393829105543219839),
                Fp::new(8880361023536540675),
                Fp::new(10336213121870908158),
            ],
            [
                Fp::new(539957049722836393),
                Fp::new(7797884473764581575),
                Fp::new(13609802008625415371),
                Fp::new(5624116829678679606),
                Fp::new(6965608708189968952),
                Fp::new(8169453397482925685),
                Fp::new(6627826384215774784),
                Fp::new(168740682822040305),
            ],
            [
                Fp::new(15215160487893668376),
                Fp::new(8271522043868394829),
                Fp::new(870964724461344173),
                Fp::new(12849944264001949235),
                Fp::new(12311579188820699166),
                Fp::new(2034712094260387411),
                Fp::new(8890917371698527517),
                Fp::new(12886631417864426936),
            ],
            [
                Fp::new(1176981420868600209),
                Fp::new(424734697148661798),
                Fp::new(17143420843872571973),
                Fp::new(13549679192117050399),
                Fp::new(6395128273261850009),
                Fp::new(1152489729274706775),
                Fp::new(7598566406553824611),
                Fp::new(17682774878372921508),
            ],
            [
                Fp::new(2132444796987003534),
                Fp::new(14654159073355726835),
                Fp::new(17792880532016924862),
                Fp::new(11974163734304157997),
                Fp::new(5795461230092020257),
                Fp::new(12426465927053499964),
                Fp::new(16566251523752661243),
                Fp::new(3558293494916770242),
            ],
        ];

        // Generated from https://github.com/KULeuven-COSIC/Marvellous
        let output_data = [
            [
                Fp::new(12181073955452979707),
                Fp::new(9158670943655755019),
                Fp::new(718742108074375543),
                Fp::new(16579473126509767433),
            ],
            [
                Fp::new(14423424906469642620),
                Fp::new(1775535680886907363),
                Fp::new(5783776085111897469),
                Fp::new(17526150000493373039),
            ],
            [
                Fp::new(1060809894344805908),
                Fp::new(10224436405935197632),
                Fp::new(4757969935448783091),
                Fp::new(9968469144996340081),
            ],
            [
                Fp::new(2578471356372762064),
                Fp::new(1095123991718431088),
                Fp::new(13477314400535042682),
                Fp::new(15769198393740759317),
            ],
            [
                Fp::new(615595465394424911),
                Fp::new(9372061817772699635),
                Fp::new(2586181052099793604),
                Fp::new(418888990138712041),
            ],
            [
                Fp::new(12776896144960608044),
                Fp::new(17366832347211106420),
                Fp::new(11107424104665113872),
                Fp::new(2742548326244730572),
            ],
            [
                Fp::new(2944630413807461704),
                Fp::new(15167548606085881838),
                Fp::new(4436539238921131753),
                Fp::new(2779939375571665567),
            ],
            [
                Fp::new(16100427607536640097),
                Fp::new(15044894735095218533),
                Fp::new(15493520606766923775),
                Fp::new(16493509091479216755),
            ],
            [
                Fp::new(8994785466594647427),
                Fp::new(17770084251690789023),
                Fp::new(5517471918631120358),
                Fp::new(12216792446601435137),
            ],
            [
                Fp::new(17069347885283780383),
                Fp::new(17478065244427861806),
                Fp::new(5108905604932996411),
                Fp::new(11410200377699509126),
            ],
        ];

        for (input, expected) in input_data.iter().zip(output_data) {
            let mut hasher = RescueHash::new();
            hasher.absorb_field(input);

            assert_eq!(expected, hasher.finalize().as_elements());
            assert_eq!(expected, RescueHash::hash_field(input).as_elements());
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
