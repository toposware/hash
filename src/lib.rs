// Copyright (c) 2021-2023 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This crate provides an implementation of different cryptographic
//! algebraic hash functions.
//!
//! This library is intended to serve as a mid-level API for cryptographic
//! protocols requiring algebraic hash functions, for instance in zk-SNARK
//! or zk-STARK proving systems.
//!
//! All hash instantiations are defined using a `Hasher` trait and can both
//! process sequences of bytes or native field elements.
//!
//! # Features
//!
//! The `f64` feature, not activated by default, allows to compile hash
//! instantiations defined over the primefield (also known as
//! Goldilocks field) Fp with p = 2**64 - 2**32 + 1.
//!
//! The `hash` library by default relies on the Rust standard library.
//! To make it suitable for use in embedded systems or WASM environments,
//! one should disable the feature by using `--no-default-features`. This
//! will make the library rely on the `alloc` crate instead for `Vec` support.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(test)]
extern crate std;

/// Custom error types
pub mod error;
/// Traits defining a hash function
pub mod traits;

#[cfg(feature = "f64")]
mod f64_utils;

mod rescue_prime;
pub use rescue_prime::*;

mod griffin;
pub use griffin::*;

mod anemoi;
pub use anemoi::*;
