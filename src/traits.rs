use super::error::TranscriptError;
use core::fmt::Debug;
use stark_curve::FieldElement;

// TODO: To support different kind of fields, we'd need them to
// implement some Field Trait which we can refer to here, and
// extend `BinaryDigest` trait with const generics for length specification.

/// Trait for interacting with an IOP
pub trait Transcript {
    /// Read challenge from the transcript
    fn read_challenge() -> Result<FieldElement, TranscriptError>;
    /// Write challenge to the transcript
    fn write_challenge() -> Result<FieldElement, TranscriptError>;
}

/// Defines output type of a cryptographic hash function.
pub trait Digest: Debug + Default + Copy + Clone + Eq + PartialEq + Send + Sync {
    /// Returns this digest serialized into an array of bytes.
    fn as_bytes(&self) -> [u8; 32];
}

/// Trait for implementing a cryptographic hash function.
pub trait Hasher {
    /// Specifies a digest type returned by this hasher.
    type Digest: Digest;

    /// Returns a hash of the provided sequence of bytes.
    fn hash(bytes: &[u8]) -> Self::Digest;

    /// Returns a hash of two digests.
    /// This method is intended for use in construction of Merkle trees.
    fn merge(values: &[Self::Digest; 2]) -> Self::Digest;

    /// Returns hash(`seed` || `value`).
    /// This method is intended for use in random coin sampling contexts.
    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest;
}
