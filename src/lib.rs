//! This crate provides Trait definitions for implementing
//! algebraic cryptographic hash functions.

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

/// The Rescue hash function over Cheetah's small
/// primefield with state width 14 and rate 7.
#[cfg(feature = "f63")]
pub mod rescue_63_14_7;

/// The Rescue hash function over Cheetah's small
/// primefield with state width 8 and rate 4.
#[cfg(feature = "f63")]
pub mod rescue_63_8_4;
