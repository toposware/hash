// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::NUM_COLUMNS;

/// Maximum Diffusion Layer matrix for Anemoi.
#[allow(unused)]
pub(crate) const MDS: [u32; NUM_COLUMNS * NUM_COLUMNS] =
    [1, 8, 7, 7, 49, 56, 8, 15, 49, 49, 1, 8, 8, 15, 7, 8];
