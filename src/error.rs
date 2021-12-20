// Copyright (c) 2021 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Errors which can occur during serialization methods.
#[derive(Debug, PartialEq)]
pub enum SerializationError {
    /// The bytes do not represent a valid field element.
    InvalidFieldElement,
}
