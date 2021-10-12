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
