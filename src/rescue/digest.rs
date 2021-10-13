//! Digest trait implementation for Rescue

use super::DIGEST_SIZE;
use crate::traits::Digest;

use stark_curve::FieldElement;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// A Rescue Digest for the Rescue Hash over Fp
pub struct RescueDigest([FieldElement; DIGEST_SIZE]);

impl RescueDigest {
    /// Returns a new Digest from a provided array
    pub fn new(value: [FieldElement; DIGEST_SIZE]) -> Self {
        Self(value)
    }

    /// Returns the wrapped digest
    pub fn as_elements(&self) -> [FieldElement; DIGEST_SIZE] {
        self.0
    }

    /// Returns a `Vec<FieldElement>` from the provided digest slice
    pub fn digests_as_elements(digests: &[Self]) -> Vec<FieldElement> {
        let mut res = Vec::with_capacity(digests.len() * DIGEST_SIZE);
        for digest in digests {
            for i in 0..DIGEST_SIZE {
                res.push(digest.0[i]);
            }
        }

        res
    }
}

impl Default for RescueDigest {
    fn default() -> Self {
        RescueDigest([FieldElement::default(); DIGEST_SIZE])
    }
}

impl Digest for RescueDigest {
    fn as_bytes(&self) -> [u8; 32] {
        // We take the first element of the digest
        // as each FieldElement is 32-bytes long.
        self.0[0].to_bytes()
    }
}
