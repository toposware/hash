// Copyright (c) 2021-2023 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::fmt::Debug;
use group::ff::Field;

/// Defines output type of a cryptographic hash function.
pub trait Digest: Debug + Default + Copy + Clone + Eq + PartialEq + Send + Sync {
    /// Returns this digest serialized into an array of bytes.
    fn to_bytes(&self) -> [u8; 32];
}

/// Trait for implementing a cryptographic hash function.
pub trait Hasher<F: Field> {
    /// Specifies a digest type returned by this hasher.
    type Digest: Digest;

    /// Returns a hash of the provided sequence of field elements.
    fn hash(bytes: &[F]) -> Self::Digest;

    /// Returns a hash of two digests.
    /// This method is intended for use in construction of Merkle trees.
    fn merge(values: &[Self::Digest; 2]) -> Self::Digest;
}
