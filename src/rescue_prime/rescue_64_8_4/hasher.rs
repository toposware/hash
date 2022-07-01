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
        state[..RATE_WIDTH].copy_from_slice(values[0].as_elements());
        state[RATE_WIDTH..STATE_WIDTH].copy_from_slice(values[1].as_elements());
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
            [Fp::zero(); 4],
            [Fp::one(); 4],
            [
                Fp::new(12696789723516079038),
                Fp::new(9199133001420111383),
                Fp::new(4917625779728435204),
                Fp::new(1296807772188121589),
            ],
            [
                Fp::new(6576572786004571242),
                Fp::new(13520483611514881578),
                Fp::new(7396734565988624997),
                Fp::new(3797367628558919976),
            ],
            [
                Fp::new(12711665381750550530),
                Fp::new(3085138097114110958),
                Fp::new(13276586898730573338),
                Fp::new(2170068693998401624),
            ],
            [
                Fp::new(1083726018176650923),
                Fp::new(5602938554164977237),
                Fp::new(9503302027124828018),
                Fp::new(17851032627776582496),
            ],
            [
                Fp::new(3460901845865360280),
                Fp::new(8874900455910869977),
                Fp::new(12961454695644130877),
                Fp::new(15224475753097411894),
            ],
            [
                Fp::new(7751822847244044845),
                Fp::new(14439542176698867963),
                Fp::new(2452137216376559421),
                Fp::new(16783572658585168490),
            ],
            [
                Fp::new(788300095521646318),
                Fp::new(13480310207084563773),
                Fp::new(5432697520099597064),
                Fp::new(5640374229052330762),
            ],
            [
                Fp::new(9585869648207771849),
                Fp::new(2964532145699725522),
                Fp::new(5111097433776572204),
                Fp::new(3948243718771775964),
            ],
            [
                Fp::new(7558703435766799826),
                Fp::new(6807316245062936198),
                Fp::new(1670996120415067330),
                Fp::new(2653701437900945479),
            ],
            [
                Fp::new(1869140707987786340),
                Fp::new(7695687736955165162),
                Fp::new(4384620636766221999),
                Fp::new(11237537366181283950),
            ],
        ];

        // Generated from https://github.com/KULeuven-COSIC/Marvellous
        let output_data = [
            [
                Fp::new(4910989335886459515),
                Fp::new(2796690540326658613),
                Fp::new(13392979779619727901),
                Fp::new(12220694230377879406),
            ],
            [
                Fp::new(14030948176935373137),
                Fp::new(6889229919436197380),
                Fp::new(15585020268064615960),
                Fp::new(15230679386058804747),
            ],
            [
                Fp::new(706470175004787691),
                Fp::new(9045846419159183300),
                Fp::new(2676418206168607609),
                Fp::new(4286167598147620515),
            ],
            [
                Fp::new(18380410717835921573),
                Fp::new(12659766701504815380),
                Fp::new(13863416848783506403),
                Fp::new(4517319948670814325),
            ],
            [
                Fp::new(3457611930991995171),
                Fp::new(15939660134846686812),
                Fp::new(3930594105400200418),
                Fp::new(8901001841441354026),
            ],
            [
                Fp::new(2174974189260558415),
                Fp::new(674423569210728397),
                Fp::new(14243685749685816500),
                Fp::new(16221541406966092001),
            ],
            [
                Fp::new(3979697094498344164),
                Fp::new(3871436604718095236),
                Fp::new(17564369428971590635),
                Fp::new(16368117003750996090),
            ],
            [
                Fp::new(14127398247547518574),
                Fp::new(14195414343668611852),
                Fp::new(2745986940484050712),
                Fp::new(8510168344648313936),
            ],
            [
                Fp::new(12357018050803044904),
                Fp::new(12200585702753246383),
                Fp::new(11782727060576301320),
                Fp::new(7544131744653844429),
            ],
            [
                Fp::new(17366033595832430932),
                Fp::new(17633758431123235206),
                Fp::new(10255355719890378928),
                Fp::new(1096989440083480883),
            ],
            [
                Fp::new(13019757464280815551),
                Fp::new(1980740933937182560),
                Fp::new(9449350348385637444),
                Fp::new(12140448948176230382),
            ],
            [
                Fp::new(18292577592561729440),
                Fp::new(7683128746905765130),
                Fp::new(2870487906647554545),
                Fp::new(7565413129633922318),
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
