//! Hasher trait implementation for Rescue

use super::digest::RescueDigest;
use super::{apply_permutation, RATE_WIDTH, STATE_WIDTH};
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

    fn hash(_bytes: &[u8]) -> Self::Digest {
        unimplemented!("not implemented")
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = [FieldElement::zero(); STATE_WIDTH];
        state[..2].copy_from_slice(&values[0].as_elements());
        state[2..4].copy_from_slice(&values[1].as_elements());
        apply_permutation(&mut state);

        RescueDigest::new([state[0], state[1]])
    }

    fn merge_with_int(_seed: Self::Digest, _value: u64) -> Self::Digest {
        unimplemented!("not implemented")
    }
}
