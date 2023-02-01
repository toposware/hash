// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::STATE_WIDTH;

/// Maximum Diffusion Layer matrix for Griffin.
#[allow(unused)]
pub(crate) const MDS: [u64; STATE_WIDTH * STATE_WIDTH] = [
    6, 4, 2, 2, 3, 2, 1, 1, 2, 6, 4, 2, 1, 3, 2, 1, 2, 2, 6, 4, 1, 1, 3, 2, 4, 2, 2, 6, 2, 1, 1, 3,
    3, 2, 1, 1, 6, 4, 2, 2, 1, 3, 2, 1, 2, 6, 4, 2, 1, 1, 3, 2, 2, 2, 6, 4, 2, 1, 1, 3, 4, 2, 2, 6,
];
