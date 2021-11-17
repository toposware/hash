//! Hasher trait implementation for Rescue

use core::convert::TryInto;

use super::digest::RescueDigest;
use super::{apply_permutation, DIGEST_SIZE, RATE_WIDTH, STATE_WIDTH};
use crate::traits::Hasher;

use stark_curve::FieldElement;

#[derive(Debug, Copy, Clone)]
/// A Rescue Hash over Fp
pub struct RescueHash {
    state: [FieldElement; STATE_WIDTH],
    idx: usize,
}

impl RescueHash {
    /// Returns a new hasher with the state initialized to all zeros.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            state: [FieldElement::zero(); STATE_WIDTH],
            idx: 0,
        }
    }

    /// Absorbs data into the hasher state.
    pub fn update(&mut self, data: &[FieldElement]) {
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
        RescueDigest::new([self.state[0], self.state[1]])
    }

    /// Returns hash of the provided data.
    pub fn digest(data: &[FieldElement]) -> RescueDigest {
        // initialize state to all zeros
        let mut state = [FieldElement::zero(); STATE_WIDTH];

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

        RescueDigest::new([state[0], state[1]])
    }

    /// Serializes the current state to an array of bytes
    pub fn to_bytes(&self) -> [u8; 136] {
        let mut res = [0u8; 136];
        assert_eq!(res.len(), STATE_WIDTH * 32 + 8);

        for (index, elem) in self.state.iter().enumerate() {
            res[index * 32..index * 32 + 32].copy_from_slice(&elem.to_bytes());
        }
        res[128..136].copy_from_slice(&(self.idx as u64).to_le_bytes());

        res
    }

    /// Returns a RescueHash from an array of bytes
    // TODO: create custom error enum including serialization
    pub fn from_bytes(bytes: &[u8; 136]) -> Self {
        let mut state = [FieldElement::zero(); STATE_WIDTH];
        let mut array = [0u8; 32];
        for index in 0..STATE_WIDTH {
            array.copy_from_slice(&bytes[index * 32..index * 32 + 32]);
            state[index] = FieldElement::from_bytes(&array).unwrap();
        }

        let mut array = [0u8; 8];
        array.copy_from_slice(&bytes[128..136]);
        let idx = u64::from_le_bytes(array) as usize;

        Self { state, idx }
    }
}

impl Hasher for RescueHash {
    type Digest = RescueDigest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // compute the number of elements required to represent the string; we will be processing
        // the string in 31-byte chunks, thus the number of elements will be equal to the number
        // of such chunks (including a potential partial chunk at the end).
        let num_elements = if bytes.len() % 31 == 0 {
            bytes.len() / 31
        } else {
            bytes.len() / 31 + 1
        };

        // initialize state to all zeros, except for the last element of the capacity part, which
        // is set to the number of elements to be hashed. this is done so that adding zero elements
        // at the end of the list always results in a different hash.
        let mut state = [FieldElement::zero(); STATE_WIDTH];
        state[STATE_WIDTH - 1] = FieldElement::new([num_elements as u64, 0, 0, 0]);

        // break the string into 31-byte chunks, convert each chunk into a field element, and
        // absorb the element into the rate portion of the state. we use 31-byte chunks because
        // every 31-byte chunk is guaranteed to map to some field element.
        let mut i = 0;
        let mut num_hashed = 0;
        let mut buf = [0u8; 32];
        for chunk in bytes.chunks(31) {
            if num_hashed + i < num_elements - 1 {
                buf[..31].copy_from_slice(chunk);
            } else {
                // if we are dealing with the last chunk, it may be smaller than 31 bytes long, so
                // we need to handle it slightly differently. we also append a byte with value 1
                // to the end of the string; this pads the string in such a way that adding
                // trailing zeros results in different hash
                let chunk_len = chunk.len();
                buf = [0u8; 32];
                buf[..chunk_len].copy_from_slice(chunk);
                buf[chunk_len] = 1;
            }

            // convert the bytes into a field element and absorb it into the rate portion of the
            // state; if the rate is filled up, apply the Rescue permutation and start absorbing
            // again from zero index.
            let mut canonical = [0u64; 4];
            let mut component = [0u8; 8];
            for part_num in 0..4 {
                component.copy_from_slice(&buf[part_num * 8..(part_num + 1) * 8]);
                canonical[part_num] = u64::from_le_bytes(component);
            }
            state[i] += FieldElement::new(canonical);
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
        // in the input list into the last state register during initialization.
        if i > 0 {
            apply_permutation(&mut state);
        }

        // return the first DIGEST_SIZE elements of the state as hash result
        let mut result = [FieldElement::zero(); DIGEST_SIZE];
        result.copy_from_slice(&state[..DIGEST_SIZE]);
        RescueDigest::new(result)
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = [FieldElement::zero(); STATE_WIDTH];
        state[..2].copy_from_slice(&values[0].as_elements());
        state[2..4].copy_from_slice(&values[1].as_elements());
        apply_permutation(&mut state);

        RescueDigest::new([state[0], state[1]])
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        // initialize the state as follows:
        // - seed is copied into the first DIGEST_SIZE elements of the state.
        // - copy the value into the DIGEST_SIZE + 1 state element
        // - set the last capacity element to DIGEST_SIZE + 1 (the number of elements to be hashed).
        let mut state = [FieldElement::zero(); STATE_WIDTH];
        state[..DIGEST_SIZE].copy_from_slice(&seed.as_elements());
        state[DIGEST_SIZE] = FieldElement::new([value, 0, 0, 0]);
        state[STATE_WIDTH - 1] = FieldElement::new([DIGEST_SIZE as u64 + 1, 0, 0, 0]);

        // apply the Rescue permutation and return the first DIGEST_SIZE elements of the state
        apply_permutation(&mut state);
        Self::Digest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }
}
