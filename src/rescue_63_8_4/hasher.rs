// Copyright (c) Toposware, Inc. 2021
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
    /// Returns a new hasher with the state initialized to all zeros.
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorbs data into the hasher state.
    pub fn update(&mut self, data: &[Fp]) {
        for &element in data {
            self.state[self.idx] += element;
            self.idx += 1;
            if self.idx % RATE_WIDTH == 0 {
                apply_permutation(&mut self.state);
                self.idx = 0;
            }
        }
    }

    /// Returns hash of the data absorbed into the hasher.
    pub fn finalize(mut self) -> RescueDigest {
        if self.idx > 0 {
            // TODO: apply proper padding
            apply_permutation(&mut self.state);
        }
        RescueDigest::new(self.state[..DIGEST_SIZE].try_into().unwrap())
    }

    /// Returns hash of the provided data.
    pub fn digest(data: &[Fp]) -> RescueDigest {
        // initialize state to all zeros
        let mut state = [Fp::zero(); STATE_WIDTH];

        let mut i = 0;
        for &element in data.iter() {
            state[i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
            }
        }

        if i > 0 {
            // TODO: apply proper padding
            apply_permutation(&mut state);
        }

        RescueDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

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

impl Hasher for RescueHash {
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

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = [Fp::zero(); STATE_WIDTH];
        state[..RATE_WIDTH].copy_from_slice(&values[0].as_elements());
        state[RATE_WIDTH..STATE_WIDTH].copy_from_slice(&values[1].as_elements());
        apply_permutation(&mut state);

        RescueDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        // initialize the state as follows:
        // - seed is copied into the first DIGEST_SIZE elements of the state.
        // - copy the value into the DIGEST_SIZE + 1 state element
        // - set the last capacity element to DIGEST_SIZE + 1 (the number of elements to be hashed).
        let mut state = [Fp::zero(); STATE_WIDTH];
        state[..DIGEST_SIZE].copy_from_slice(&seed.as_elements());
        state[DIGEST_SIZE] = Fp::new(value);
        state[STATE_WIDTH - 1] = Fp::new(DIGEST_SIZE as u64 + 1);

        // apply the Rescue permutation and return the first DIGEST_SIZE elements of the state
        apply_permutation(&mut state);
        Self::Digest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheetah::group::ff::Field;
    use rand::thread_rng;

    #[test]
    fn test_rescue_hash() {
        // Hardcoded input / output list generated from the
        // Sagemath code at https://github.com/KULeuven-COSIC/Marvellous

        let input_data = [
            [Fp::zero(); 4],
            [Fp::one(); 4],
            [
                Fp::new(0x3ebcb28a51819c54),
                Fp::new(0x14e6aa961c43b5d2),
                Fp::new(0x3f13f04c69dfa8a8),
                Fp::new(0x325296b555707836),
            ],
            [
                Fp::new(0xd8bdb2ddd5a119f),
                Fp::new(0x99bdeece24b27d0),
                Fp::new(0x26c8a6ed4938f726),
                Fp::new(0x21ea4b8f6906a37c),
            ],
            [
                Fp::new(0x7154fcaf808e55d),
                Fp::new(0xbfa17b17bb3692c),
                Fp::new(0xebcc2606b1621ef),
                Fp::new(0x2821c6825afa0c28),
            ],
            [
                Fp::new(0x37405d66b92d7341),
                Fp::new(0x2aa7ced84e3c3ab2),
                Fp::new(0x3f915540c04ec33d),
                Fp::new(0x3f52b8d6ca4dffac),
            ],
            [
                Fp::new(0x99c965133f3cf48),
                Fp::new(0x384db0fb56389e10),
                Fp::new(0x1a140180f0ce7357),
                Fp::new(0x92903756226e870),
            ],
            [
                Fp::new(0x2a8b79b655141525),
                Fp::new(0x20b7ddca84fa8a16),
                Fp::new(0x12cab5c433b1e0d7),
                Fp::new(0x6be0c54090bfb63),
            ],
            [
                Fp::new(0x3ae87a489fdf983f),
                Fp::new(0x1d06503e54b63e8b),
                Fp::new(0x3006f5e7733d5af2),
                Fp::new(0x3a65d12191c6b211),
            ],
            [
                Fp::new(0x303157e5f79bf329),
                Fp::new(0xc04c01a2a940b5c),
                Fp::new(0x325aac3c0d2184ab),
                Fp::new(0x3953588a9096fb70),
            ],
            [
                Fp::new(0x19c5b50560b52f00),
                Fp::new(0x623d62022835b5e),
                Fp::new(0x34fcc29c0e564474),
                Fp::new(0x13101cef517ff985),
            ],
            [
                Fp::new(0x94cfecc8f4d10b7),
                Fp::new(0x2b88a61ca0de9c34),
                Fp::new(0x3e638473a5f2fea0),
                Fp::new(0x18d0a463ac4ad17b),
            ],
        ];

        // Generated from https://github.com/KULeuven-COSIC/Marvellous
        let output_data = [
            [
                Fp::new(0x1d7d1c904e7858c5),
                Fp::new(0x2c96361cdcad4b01),
                Fp::new(0xe857e25fa4dadfe),
                Fp::new(0x310e98831879bcef),
            ],
            [
                Fp::new(0x3536bc139ca6b861),
                Fp::new(0x1306d52287bffbce),
                Fp::new(0x291070f39e21f454),
                Fp::new(0x224f65c00e786325),
            ],
            [
                Fp::new(0x26f988d255aa61ea),
                Fp::new(0x38e3beca15a9dbb1),
                Fp::new(0x31c8e37564a9eaf1),
                Fp::new(0xa5a58db61c7fe73),
            ],
            [
                Fp::new(0xf448544866ad5c0),
                Fp::new(0x332edb57b9db1a0f),
                Fp::new(0x76721621709317),
                Fp::new(0x36a6e8f80253d3bf),
            ],
            [
                Fp::new(0x40f68a0cdfd83d7f),
                Fp::new(0x3a1b631af1d1f29c),
                Fp::new(0xdd2dfce747f1def),
                Fp::new(0x1783f053a2606022),
            ],
            [
                Fp::new(0x25075a62a01f2a77),
                Fp::new(0x2953de2062f4087c),
                Fp::new(0x2e5d1233c626ca1d),
                Fp::new(0x380c1c9cecb7a101),
            ],
            [
                Fp::new(0x19426629a1e48dc6),
                Fp::new(0x1220a39e48d5c81b),
                Fp::new(0x286fabd68bd7c7af),
                Fp::new(0xde9a3e1b624a53f),
            ],
            [
                Fp::new(0x40dd6704acf1a64b),
                Fp::new(0x1f842b587300d29e),
                Fp::new(0x20e092ba9548eaf7),
                Fp::new(0x69b936db4bc69ee),
            ],
            [
                Fp::new(0x1d1815f977bf6c71),
                Fp::new(0x121647a2026c9915),
                Fp::new(0x3827d78704a0a185),
                Fp::new(0x2d30521cc662af88),
            ],
            [
                Fp::new(0x159872f54c657b9e),
                Fp::new(0x3c829b5b8f658c28),
                Fp::new(0x352ce855748af7b7),
                Fp::new(0x3a3aaa39d38c7c1a),
            ],
            [
                Fp::new(0x3cc422c2f53d0ce1),
                Fp::new(0x6701c35966044f),
                Fp::new(0xb3d4102e4ec3a09),
                Fp::new(0x4a7e6911f41970a),
            ],
            [
                Fp::new(0x352f467a70f4e1d1),
                Fp::new(0x2a18c79e44945f19),
                Fp::new(0xdfd6b65ae97860b),
                Fp::new(0x5973ca53a486adc),
            ],
        ];

        for (input, expected) in input_data.iter().zip(output_data) {
            let mut hasher = RescueHash::new();
            hasher.update(input);

            assert_eq!(expected, hasher.finalize().as_elements());
            assert_eq!(expected, RescueHash::digest(input).as_elements());
        }
    }

    #[test]
    fn test_serialization() {
        let mut rng = thread_rng();

        for _ in 0..100 {
            let mut data = [Fp::zero(); DIGEST_SIZE];
            for e in data.iter_mut() {
                *e = Fp::random(&mut rng);
            }

            let mut hasher = RescueHash::new();
            hasher.update(&data);

            let bytes = hasher.to_bytes();

            assert_eq!(hasher, RescueHash::from_bytes(&bytes).unwrap());
        }

        // Test invalid encoding
        let mut data = [Fp::zero(); DIGEST_SIZE];
        for e in data.iter_mut() {
            *e = Fp::random(&mut rng);
        }

        let mut hasher = RescueHash::new();
        hasher.update(&data);

        let mut bytes = hasher.to_bytes();
        bytes[7] = 0b1111_1111;

        assert!(RescueHash::from_bytes(&bytes).is_err());
    }
}
