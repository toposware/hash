#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use stark_curve::FieldElement;

/// Digest for Rescue
pub mod digest;
/// Hasher for Rescue
pub mod hasher;
/// MDS matrix for Rescue
pub mod mds;
/// Round constants for Rescue
pub mod round_constants;
/// S-Box for Rescue
pub mod sbox;

// RESCUE CONSTANTS
// ================================================================================================

/// Function state is set to 4 field elements or 128 bytes;
/// 2 elements of the state are reserved for capacity
pub const STATE_WIDTH: usize = 4;
/// 2 elements of the state are reserved for rate
pub const RATE_WIDTH: usize = 2;

/// Two elements (64-bytes) are returned as digest.
pub const DIGEST_SIZE: usize = 2;

/// The number of rounds is set to 14 to provide 128-bit security level with 50% security margin;
/// computed using algorithm 7 from <https://eprint.iacr.org/2020/1143.pdf>
pub const NUM_HASH_ROUNDS: usize = 14;

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
fn square_assign_multi(n: &mut FieldElement, num_times: usize) {
    for _ in 0..num_times {
        *n = n.square();
    }
}

#[inline(always)]
#[allow(clippy::needless_range_loop)]
/// Applies exponentiation of the current hash
/// state elements with the Rescue S-Box.
pub fn apply_sbox(state: &mut [FieldElement]) {
    for i in 0..STATE_WIDTH {
        // alpha = 3
        state[i] *= state[i].square();
    }
}

#[inline(always)]
#[allow(clippy::needless_range_loop)]
/// Applies exponentiation of the current hash state
/// elements with the Rescue inverse S-Box.
pub fn apply_inv_sbox(state: &mut [FieldElement]) {
    // found using https://github.com/kwantam/addchain for INV_ALPHA
    for i in 0..STATE_WIDTH {
        let mut t2 = state[i]; //              0: 1
        let mut t1 = t2.square(); //           1: 2
        let mut t0 = t1 * t2; //               2: 3
        let mut t3 = t1.square(); //           3: 4
        let t4 = t0.square(); //               4: 6
        t0 = t4 * t3; //                       5: 10
        t1 = t0 * t4; //                       6: 16
        t0 = t0.square(); //                   7: 20
        t2 *= t0; //                           8: 21
        t1 = t2 * t1; //                       9: 37
        t0 = t0.square(); //                  10: 40
        t1 *= t4; //                          11: 43
        t0 = t0.square(); //                  12: 80
        t0 *= t2; //                          13: 101
        t3 *= t0; //                          14: 105
        t0 = t3.square(); //                  15: 210
        t0 *= t3; //                          16: 315
        square_assign_multi(&mut t0, 2); //   18: 1260
        t3 *= t0; //                          19: 1365
        t0 = t3.square(); //                  20: 2730
        square_assign_multi(&mut t0, 11); //  31: 5591040
        t0 *= t3; //                          32: 5592405
        square_assign_multi(&mut t0, 12); //  44: 22906490880
        t0 *= t3; //                          45: 22906492245
        square_assign_multi(&mut t0, 12); //  57: 93824992235520
        t0 *= t3; //                          58: 93824992236885
        square_assign_multi(&mut t0, 7); //   65: 12009599006321280
        t0 *= t1; //                          66: 12009599006321323
        square_assign_multi(&mut t0, 16); //  82: 787061080478274224128
        t0 *= t3; //                          83: 787061080478274225493
        square_assign_multi(&mut t0, 12); //  95: 3223802185639011227619328
        t0 *= t3; //                          96: 3223802185639011227620693
        square_assign_multi(&mut t0, 12); // 108: 13204693752377389988334358528
        t0 *= t3; //                         109: 13204693752377389988334359893
        square_assign_multi(&mut t0, 12); // 121: 54086425609737789392217538121728
        t0 *= t3; //                         122: 54086425609737789392217538123093
        square_assign_multi(&mut t0, 12); // 134: 221537999297485985350523036152188928
        t0 *= t3; //                         135: 221537999297485985350523036152190293
        square_assign_multi(&mut t0, 12); // 147: 907419645122502595995742356079371440128
        t0 *= t3; //                         148: 907419645122502595995742356079371441493
        square_assign_multi(&mut t0, 12); // 160: 3716790866421770633198560690501105424355328
        t0 *= t3; //                         161: 3716790866421770633198560690501105424356693
        square_assign_multi(&mut t0, 12); // 173: 15223975388863572513581304588292527818165014528
        t0 *= t3; //                         174: 15223975388863572513581304588292527818165015893
        square_assign_multi(&mut t0, 12); // 186: 62357403192785193015629023593646193943203905097728
        t0 *= t3; //                         187: 62357403192785193015629023593646193943203905099093
        square_assign_multi(&mut t0, 12); // 199: 255415923477648150592016480639574810391363195285884928
        t0 *= t3; //                         200: 255415923477648150592016480639574810391363195285886293
        square_assign_multi(&mut t0, 12); // 212: 1046183622564446824824899504699698423363023647890990256128
        t0 *= t3; //                         213: 1046183622564446824824899504699698423363023647890990257493
        square_assign_multi(&mut t0, 12); // 225: 4285168118023974194482788371249964742094944861761496094691328
        t0 *= t3; //                         226: 4285168118023974194482788371249964742094944861761496094692693
        square_assign_multi(&mut t0, 12); // 238: 17552048611426198300601501168639855583620894153775088003861270528
        t0 *= t3; //                         239: 17552048611426198300601501168639855583620894153775088003861271893
        square_assign_multi(&mut t0, 12); // 251: 71893191112401708239263748786748848470511182453862760463815769673728
        t0 *= t3; //                         252: 71893191112401708239263748786748848470511182453862760463815769675093
        square_assign_multi(&mut t0, 12); // 264: 294474510796397396948024315030523283335213803331021866859789392589180928
        t0 *= t3; //                         265: 294474510796397396948024315030523283335213803331021866859789392589182293
        square_assign_multi(&mut t0, 6); //  271: 18846368690969433404673556161953490133453683413185399479026521125707666752
        t0 *= t2; //                         272: 18846368690969433404673556161953490133453683413185399479026521125707666773
        square_assign_multi(&mut t0, 7); //  279: 2412335192444087475798215188730046737082071476887731133315394704090581346944
        state[i] = t0 * t1; //               280: 2412335192444087475798215188730046737082071476887731133315394704090581346987
    }
}

#[inline(always)]
#[allow(clippy::needless_range_loop)]
/// Applies matrix-vector multiplication of the current
/// hash state with the Rescue MDS matrix.
pub fn apply_mds(state: &mut [FieldElement]) {
    let mut result = [FieldElement::zero(); STATE_WIDTH];
    let mut temp = [FieldElement::zero(); STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            temp[j] = mds::MDS[i * STATE_WIDTH + j] * state[j];
        }

        for j in 0..STATE_WIDTH {
            result[i] += temp[j];
        }
    }
    state.copy_from_slice(&result);
}

#[inline(always)]
#[allow(clippy::needless_range_loop)]
/// Applies matrix-vector multiplication of the current
/// hash state with the inverse Rescue MDS matrix.
pub fn apply_inv_mds(state: &mut [FieldElement]) {
    let mut result = [FieldElement::zero(); STATE_WIDTH];
    let mut temp = [FieldElement::zero(); STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            temp[j] = mds::INV_MDS[i * STATE_WIDTH + j] * state[j];
        }

        for j in 0..STATE_WIDTH {
            result[i] += temp[j];
        }
    }
    state.copy_from_slice(&result);
}

// RESCUE PERMUTATION
// ================================================================================================

/// Applies Rescue-XLIX permutation to the provided state.
pub fn apply_permutation(state: &mut [FieldElement; STATE_WIDTH]) {
    for i in 0..NUM_HASH_ROUNDS {
        apply_round(state, i);
    }
}

/// Rescue-XLIX round function;
/// implementation based on algorithm 3 of <https://eprint.iacr.org/2020/1143.pdf>
#[inline(always)]
pub fn apply_round(state: &mut [FieldElement], step: usize) {
    // determine which round constants to use
    let ark = round_constants::ARK[step % NUM_HASH_ROUNDS];

    // apply first half of Rescue round
    apply_sbox(state);
    apply_mds(state);
    for i in 0..STATE_WIDTH {
        state[i] += ark[i];
    }

    // apply second half of Rescue round
    apply_inv_sbox(state);
    apply_mds(state);
    for i in 0..STATE_WIDTH {
        state[i] += ark[STATE_WIDTH + i];
    }
}
