// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{NUM_HASH_ROUNDS, STATE_WIDTH};
use cheetah::Fp;

/// Additive round constants c_i for Griffin.
pub(crate) const ARK: [[Fp; STATE_WIDTH]; NUM_HASH_ROUNDS - 1] = [
    [
        Fp::new(9692712401870945221),
        Fp::new(7618007584389424767),
        Fp::new(5248032629877155397),
        Fp::new(3331263627507477698),
        Fp::new(860199187432911550),
        Fp::new(10360526140302824670),
        Fp::new(5014858186237911359),
        Fp::new(4161019260461204222),
    ],
    [
        Fp::new(2649891723669882704),
        Fp::new(15035697086627576083),
        Fp::new(14140087988207356741),
        Fp::new(357780579603925138),
        Fp::new(273712483418536090),
        Fp::new(348552596175072640),
        Fp::new(11116926243792475367),
        Fp::new(2475357435469270767),
    ],
    [
        Fp::new(9513699262061178678),
        Fp::new(11735848814479196467),
        Fp::new(12888397717055708631),
        Fp::new(15194236579723079985),
        Fp::new(14734897209064082180),
        Fp::new(9352307275330595094),
        Fp::new(2536293522055086772),
        Fp::new(1551701365424645656),
    ],
    [
        Fp::new(17180574791560887028),
        Fp::new(10973179380721509279),
        Fp::new(15451549433162538377),
        Fp::new(11230437049044589131),
        Fp::new(14416448585168854586),
        Fp::new(13520950449774622599),
        Fp::new(14110026253178816443),
        Fp::new(7562226163074683487),
    ],
    [
        Fp::new(15625584526294513461),
        Fp::new(12868717640985007163),
        Fp::new(5045176603305276542),
        Fp::new(6821445918259551845),
        Fp::new(15049718154108882541),
        Fp::new(676731535772312475),
        Fp::new(14779363889066167393),
        Fp::new(17108914943169063073),
    ],
    [
        Fp::new(17529530613938644968),
        Fp::new(13801329800663243071),
        Fp::new(12666329335088484031),
        Fp::new(10289051774796875319),
        Fp::new(46795987162557096),
        Fp::new(8590445841426612555),
        Fp::new(7174111149249058757),
        Fp::new(5820086182616968416),
    ],
    [
        Fp::new(18362920096257427776),
        Fp::new(18336590902193839311),
        Fp::new(17082524670299631881),
        Fp::new(2963587252058675526),
        Fp::new(2307961039727424150),
        Fp::new(17730937419471724169),
        Fp::new(13943985318970238834),
        Fp::new(8435322757080491462),
    ],
];
