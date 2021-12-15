// Copyright (c) Toposware, Inc. 2021
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Digest trait implementation for Rescue

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::DIGEST_SIZE;
use crate::traits::Digest;

use cheetah::Fp;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// A Rescue Digest for the Rescue Hash over Fp
pub struct RescueDigest([Fp; DIGEST_SIZE]);

impl RescueDigest {
    /// Returns a new Digest from a provided array
    pub fn new(value: [Fp; DIGEST_SIZE]) -> Self {
        Self(value)
    }

    /// Returns the wrapped digest
    pub fn as_elements(&self) -> [Fp; DIGEST_SIZE] {
        self.0
    }

    /// Returns a `Vec<Fp>` from the provided digest slice
    pub fn digests_as_elements(digests: &[Self]) -> Vec<Fp> {
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
        RescueDigest([Fp::default(); DIGEST_SIZE])
    }
}

impl Digest for RescueDigest {
    fn as_bytes(&self) -> [u8; 32] {
        let mut digest = [0u8; 32];
        digest[0..8].copy_from_slice(&self.0[0].to_bytes());
        digest[8..16].copy_from_slice(&self.0[1].to_bytes());
        digest[16..24].copy_from_slice(&self.0[2].to_bytes());
        digest[24..32].copy_from_slice(&self.0[3].to_bytes());

        digest
    }
}
