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
    pub fn to_bytes(&self) -> [u8; 104] {
        let mut res = [0u8; 104];
        assert_eq!(res.len(), STATE_WIDTH * 8 + 8);

        for (index, elem) in self.state.iter().enumerate() {
            res[index * 8..index * 8 + 8].copy_from_slice(&elem.to_bytes());
        }
        res[96..104].copy_from_slice(&(self.idx as u64).to_le_bytes());

        res
    }

    /// Returns a GriffinHash from an array of bytes
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

        GriffinDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = [Fp::zero(); STATE_WIDTH];
        state[..DIGEST_SIZE].copy_from_slice(values[0].as_elements());
        state[DIGEST_SIZE..RATE_WIDTH].copy_from_slice(values[1].as_elements());
        apply_permutation(&mut state);

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

        GriffinDigest::new(self.state[..DIGEST_SIZE].try_into().unwrap())
    }
}
