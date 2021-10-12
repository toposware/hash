//! This crate provides a Trait definition for implementing hash functions
//! as well as a custom implementation of the Rescue hash function over the
//! prime field of order
//! p = 0x800000000000011000000000000000000000000000000000000000000000001.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

/// Custom error types
pub mod error;
/// Traits defining a hash function
pub mod traits;

/// The Rescue hash function
pub mod rescue;
