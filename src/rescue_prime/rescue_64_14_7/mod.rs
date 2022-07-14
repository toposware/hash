// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::traits::RescuePrimeHasher;
use cheetah::Fp;

use crate::f64_utils::{apply_rescue_inv_sbox, apply_rescue_sbox};

/// Digest for Rescue
mod digest;
/// Hasher for Rescue
mod hasher;
/// MDS matrix for Rescue
mod mds;
/// Round constants for Rescue
mod round_constants;

pub use digest::RescueDigest;
pub use hasher::RescueHash;

// RESCUE CONSTANTS
// ================================================================================================

/// Function state is set to 14 field elements or 112 bytes;
/// 7 elements of the state are reserved for capacity
pub const STATE_WIDTH: usize = 14;
/// 7 elements of the state are reserved for rate
pub const RATE_WIDTH: usize = 7;

/// Seven elements (56-bytes) are returned as digest.
pub const DIGEST_SIZE: usize = 7;

/// The number of rounds is set to 7 to provide 128-bit security level with 40% security margin;
/// computed using algorithm 7 from <https://eprint.iacr.org/2020/1143.pdf>
pub const NUM_HASH_ROUNDS: usize = 7;

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
/// Applies matrix-vector multiplication of the current
/// hash state with the Rescue MDS matrix.
pub(crate) fn apply_mds(state: &mut [Fp; STATE_WIDTH]) {
    let mut result = [Fp::zero(); STATE_WIDTH];
    for (i, r) in result.iter_mut().enumerate() {
        for (j, s) in state.iter().enumerate() {
            *r += mds::MDS[i * STATE_WIDTH + j] * s;
        }
    }

    state.copy_from_slice(&result);
}

// RESCUE PERMUTATION
// ================================================================================================

/// Applies Rescue-XLIX permutation to the provided state.
pub(crate) fn apply_permutation(state: &mut [Fp; STATE_WIDTH]) {
    for i in 0..NUM_HASH_ROUNDS {
        apply_round(state, i);
    }
}

/// Rescue-XLIX round function;
/// implementation based on algorithm 3 of <https://eprint.iacr.org/2020/1143.pdf>
#[inline(always)]
pub(crate) fn apply_round(state: &mut [Fp; STATE_WIDTH], step: usize) {
    // determine which round constants to use
    let ark = round_constants::ARK[step % NUM_HASH_ROUNDS];

    // apply first half of Rescue round
    apply_rescue_sbox(state);
    apply_mds(state);
    for i in 0..STATE_WIDTH {
        state[i] += ark[i];
    }

    // apply second half of Rescue round
    apply_rescue_inv_sbox(state);
    apply_mds(state);
    for i in 0..STATE_WIDTH {
        state[i] += ark[STATE_WIDTH + i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    const INV_MDS: [Fp; STATE_WIDTH * STATE_WIDTH] = [
        Fp::new(14993335630867716184),
        Fp::new(14798903896630488394),
        Fp::new(11506106850397771938),
        Fp::new(16128074640045476116),
        Fp::new(17113496857259246357),
        Fp::new(5442611323918762194),
        Fp::new(12839728378879979395),
        Fp::new(1444062866257519826),
        Fp::new(17897511721620345619),
        Fp::new(17379608493824643859),
        Fp::new(6965499108410563234),
        Fp::new(8768393183691359259),
        Fp::new(8779487712422348330),
        Fp::new(11963875960505038185),
        Fp::new(11081720647215285930),
        Fp::new(13977530232301203627),
        Fp::new(4825537341096580023),
        Fp::new(2250559455744722135),
        Fp::new(18350405667350934436),
        Fp::new(11409083100678954380),
        Fp::new(5330414892264725507),
        Fp::new(3182990017273081535),
        Fp::new(12975472339635813832),
        Fp::new(4983592390008722172),
        Fp::new(1284832831924047505),
        Fp::new(1491542986664064481),
        Fp::new(614978071426829709),
        Fp::new(475060373487956334),
        Fp::new(5672312356967338607),
        Fp::new(17663420325404438323),
        Fp::new(15368494051886985658),
        Fp::new(15628487472432263281),
        Fp::new(10489578978348158576),
        Fp::new(17388609333891694753),
        Fp::new(16748353396133059277),
        Fp::new(6654229984476661895),
        Fp::new(16178267359579524272),
        Fp::new(4575077049189296310),
        Fp::new(7352234333961101038),
        Fp::new(6522980281942879977),
        Fp::new(4437419368469978143),
        Fp::new(2894488262633294459),
        Fp::new(2593644674279424991),
        Fp::new(18150556418450974746),
        Fp::new(11154104500237812303),
        Fp::new(10015038591768695035),
        Fp::new(2012006438531081507),
        Fp::new(1530099499423762054),
        Fp::new(8663455652150043897),
        Fp::new(15952320225399867814),
        Fp::new(2064118037203799776),
        Fp::new(2387376314500056292),
        Fp::new(5637402297982540394),
        Fp::new(5444918788251444613),
        Fp::new(3596349665661430513),
        Fp::new(3032329243231987671),
        Fp::new(12499748289481694065),
        Fp::new(9793128035089358752),
        Fp::new(8000646412381157575),
        Fp::new(18248291991066914012),
        Fp::new(16665369425945272154),
        Fp::new(9323539079989089293),
        Fp::new(5559091291637197985),
        Fp::new(16829241485243745486),
        Fp::new(746261824484690207),
        Fp::new(809204964671228974),
        Fp::new(12319492478778090748),
        Fp::new(2537477842082252721),
        Fp::new(10052550903270150595),
        Fp::new(5743164461781247681),
        Fp::new(17859223552774501372),
        Fp::new(4181685039903611743),
        Fp::new(10353560635970908567),
        Fp::new(2011177688748739137),
        Fp::new(15026866187047313569),
        Fp::new(10466752897530287954),
        Fp::new(18127714290428658661),
        Fp::new(8127717631151119630),
        Fp::new(6617022917683291459),
        Fp::new(5362208887735954804),
        Fp::new(16423519945875810556),
        Fp::new(16415615092464949567),
        Fp::new(4817169288248897528),
        Fp::new(11783718499752630022),
        Fp::new(13025416715530170535),
        Fp::new(13782204750711238385),
        Fp::new(15371411199983001899),
        Fp::new(15964172590899652392),
        Fp::new(11001038020621701859),
        Fp::new(18360655445408894501),
        Fp::new(13411152899402758382),
        Fp::new(8875969528504162777),
        Fp::new(7898708996896403266),
        Fp::new(10715048207861747289),
        Fp::new(15007276890395202394),
        Fp::new(12473613235016045575),
        Fp::new(15816876921209414533),
        Fp::new(12763895291705449424),
        Fp::new(5444017148568217264),
        Fp::new(12282104814486684309),
        Fp::new(10453937780409152913),
        Fp::new(2526911823094062058),
        Fp::new(24323685703322818),
        Fp::new(17340193856893488350),
        Fp::new(3761394215789328168),
        Fp::new(10802314039899926488),
        Fp::new(9216005878242243182),
        Fp::new(138893391333949377),
        Fp::new(17392833794856732252),
        Fp::new(2548491937752013743),
        Fp::new(2658305816963936327),
        Fp::new(16090736232494448678),
        Fp::new(18116894409624479910),
        Fp::new(11156062159571775002),
        Fp::new(10857200659603745065),
        Fp::new(2126055916298629795),
        Fp::new(999239427477509977),
        Fp::new(3297452210655251633),
        Fp::new(15235695771538045036),
        Fp::new(10080169646196115150),
        Fp::new(8150368675517856252),
        Fp::new(10913246839858524270),
        Fp::new(10139780225225524153),
        Fp::new(4565633178473317128),
        Fp::new(15366380279451559708),
        Fp::new(8123029086409757169),
        Fp::new(8803183078427061640),
        Fp::new(8828216416604758010),
        Fp::new(12724738604443472428),
        Fp::new(11555981705004081257),
        Fp::new(16120463185456136150),
        Fp::new(10715518030378439329),
        Fp::new(6314681646840799864),
        Fp::new(11838879594773673494),
        Fp::new(11201825909558104076),
        Fp::new(6785136189644197197),
        Fp::new(16122084631907503796),
        Fp::new(10155213474557895899),
        Fp::new(12013180617159146112),
        Fp::new(4394849470561405317),
        Fp::new(17589179587703577100),
        Fp::new(11280381444602388107),
        Fp::new(10953614755096807718),
        Fp::new(17894706874534440979),
        Fp::new(4684069970475257872),
        Fp::new(4394812134023957638),
        Fp::new(11453312524526892380),
        Fp::new(10106513255994750642),
        Fp::new(18280470387592166182),
        Fp::new(17868095946998749129),
        Fp::new(4125597017913045460),
        Fp::new(421604073621018734),
        Fp::new(17811486578691862934),
        Fp::new(710108003541759694),
        Fp::new(8437673252506498159),
        Fp::new(1004298000453198099),
        Fp::new(17273750873684998509),
        Fp::new(5148947297137766130),
        Fp::new(14442049344288732218),
        Fp::new(10046725153481091824),
        Fp::new(14047039563285745503),
        Fp::new(2694066465773268201),
        Fp::new(16174664436342279747),
        Fp::new(511777579819286789),
        Fp::new(4663981674172737657),
        Fp::new(2255562705901502624),
        Fp::new(10847772808718596359),
        Fp::new(3132155260921804108),
        Fp::new(2884907379164397699),
        Fp::new(2639760272890307697),
        Fp::new(10966308319215875293),
        Fp::new(12635391191933026504),
        Fp::new(6488371086224535855),
        Fp::new(9236525573843665583),
        Fp::new(5500136669219657527),
        Fp::new(6677433475161759208),
        Fp::new(12092869882020115244),
        Fp::new(7178320692373716212),
        Fp::new(6198438978446419982),
        Fp::new(5801668697611813134),
        Fp::new(11772796211815485979),
        Fp::new(10607535986566730010),
        Fp::new(33352503433004487),
        Fp::new(16932604008709416158),
        Fp::new(12431819051116679897),
        Fp::new(13589069022946923053),
        Fp::new(1939608105800760519),
        Fp::new(704608913578453245),
        Fp::new(15215522382131574909),
        Fp::new(3912755105947460029),
        Fp::new(1375690382209801450),
        Fp::new(16087218708262598217),
        Fp::new(4600218579415278405),
        Fp::new(8722234088638090297),
        Fp::new(6108148037370562940),
        Fp::new(9027615526926902321),
    ];

    /// Applies matrix-vector multiplication of the current
    /// hash state with the inverse Rescue MDS matrix.
    fn apply_inv_mds(state: &mut [Fp; STATE_WIDTH]) {
        let mut result = [Fp::zero(); STATE_WIDTH];
        for (i, r) in result.iter_mut().enumerate() {
            for (j, s) in state.iter().enumerate() {
                *r += INV_MDS[i * STATE_WIDTH + j] * s;
            }
        }

        state.copy_from_slice(&result);
    }

    #[test]
    fn test_mds() {
        let mut state = [Fp::zero(); STATE_WIDTH];
        let mut rng = OsRng;

        for _ in 0..100 {
            for s in state.iter_mut() {
                *s = Fp::random(&mut rng);
            }

            let state_copy = state;
            apply_mds(&mut state);

            // Check that matrix multiplication was consistent
            apply_inv_mds(&mut state);
            assert_eq!(state, state_copy);
        }
    }
}
