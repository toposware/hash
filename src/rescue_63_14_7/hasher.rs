//! Hasher trait implementation for Rescue

use core::convert::TryInto;

use super::digest::RescueDigest;
use super::{apply_permutation, DIGEST_SIZE, RATE_WIDTH, STATE_WIDTH};
use crate::traits::Hasher;

use cheetah::Fp;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// A Rescue Hash over Fp
pub struct RescueHash {
    state: [Fp; STATE_WIDTH],
    idx: usize,
}

impl RescueHash {
    /// Returns a new hasher with the state initialized to all zeros.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            state: [Fp::zero(); STATE_WIDTH],
            idx: 0,
        }
    }

    /// Absorbs data into the hasher state.
    pub fn update(&mut self, data: &[Fp]) {
        for &element in data {
            self.state[self.idx] += element;
            self.idx += 1;
            if self.idx % RATE_WIDTH == 0 {
                apply_permutation(&mut self.state);
                self.idx = 0;
            }
        }
    }

    /// Returns hash of the data absorbed into the hasher.
    pub fn finalize(mut self) -> RescueDigest {
        if self.idx > 0 {
            // TODO: apply proper padding
            apply_permutation(&mut self.state);
        }
        RescueDigest::new(self.state[..DIGEST_SIZE].try_into().unwrap())
    }

    /// Returns hash of the provided data.
    pub fn digest(data: &[Fp]) -> RescueDigest {
        // initialize state to all zeros
        let mut state = [Fp::zero(); STATE_WIDTH];

        let mut i = 0;
        for &element in data.iter() {
            state[i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
            }
        }

        if i > 0 {
            // TODO: apply proper padding
            apply_permutation(&mut state);
        }

        RescueDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    /// Serializes the current state to an array of bytes
    pub fn to_bytes(&self) -> [u8; 120] {
        let mut res = [0u8; 120];
        assert_eq!(res.len(), STATE_WIDTH * 8 + 8);

        for (index, elem) in self.state.iter().enumerate() {
            res[index * 8..index * 8 + 8].copy_from_slice(&elem.to_bytes());
        }
        res[112..120].copy_from_slice(&(self.idx as u64).to_le_bytes());

        res
    }

    /// Returns a RescueHash from an array of bytes
    // TODO: create custom error enum including serialization
    pub fn from_bytes(bytes: &[u8; 120]) -> Self {
        let mut state = [Fp::zero(); STATE_WIDTH];
        let mut array = [0u8; 8];
        for index in 0..STATE_WIDTH {
            array.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
            state[index] = Fp::from_bytes(&array).unwrap();
        }

        array.copy_from_slice(&bytes[112..120]);
        let idx = u64::from_le_bytes(array) as usize;

        Self { state, idx }
    }
}

impl Hasher for RescueHash {
    type Digest = RescueDigest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // compute the number of elements required to represent the string; we will be processing
        // the string in 7-byte chunks, thus the number of elements will be equal to the number
        // of such chunks (including a potential partial chunk at the end).
        let num_elements = if bytes.len() % 7 == 0 {
            bytes.len() / 7
        } else {
            bytes.len() / 7 + 1
        };

        // initialize state to all zeros, except for the last element of the capacity part, which
        // is set to the number of elements to be hashed. this is done so that adding zero elements
        // at the end of the list always results in a different hash.
        let mut state = [Fp::zero(); STATE_WIDTH];
        state[STATE_WIDTH - 1] = Fp::new(num_elements as u64);

        // break the string into 7-byte chunks, convert each chunk into a field element, and
        // absorb the element into the rate portion of the state. we use 7-byte chunks because
        // every 7-byte chunk is guaranteed to map to some field element.
        let mut i = 0;
        let mut num_hashed = 0;
        let mut buf = [0u8; 8];
        for chunk in bytes.chunks(7) {
            if num_hashed + i < num_elements - 1 {
                buf[..7].copy_from_slice(chunk);
            } else {
                // if we are dealing with the last chunk, it may be smaller than 7 bytes long, so
                // we need to handle it slightly differently. we also append a byte with value 1
                // to the end of the string; this pads the string in such a way that adding
                // trailing zeros results in different hash
                let chunk_len = chunk.len();
                buf = [0u8; 8];
                buf[..chunk_len].copy_from_slice(chunk);
                buf[chunk_len] = 1;
            }

            // convert the bytes into a field element and absorb it into the rate portion of the
            // state; if the rate is filled up, apply the Rescue permutation and start absorbing
            // again from zero index.
            state[i] += Fp::new(u64::from_le_bytes(buf));
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
                num_hashed += RATE_WIDTH;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the Rescue permutation.
        // we don't need to apply any extra padding because we injected total number of elements
        // in the input list into the capacity portion of the state during initialization.
        if i > 0 {
            apply_permutation(&mut state);
        }

        // return the first DIGEST_SIZE elements of the state as hash result
        RescueDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = [Fp::zero(); STATE_WIDTH];
        state[..RATE_WIDTH].copy_from_slice(&values[0].as_elements());
        state[RATE_WIDTH..STATE_WIDTH].copy_from_slice(&values[1].as_elements());
        apply_permutation(&mut state);

        RescueDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        // initialize the state as follows:
        // - seed is copied into the first DIGEST_SIZE elements of the state.
        // - copy the value into the DIGEST_SIZE + 1 state element
        // - set the last capacity element to DIGEST_SIZE + 1 (the number of elements to be hashed).
        let mut state = [Fp::zero(); STATE_WIDTH];
        state[..DIGEST_SIZE].copy_from_slice(&seed.as_elements());
        state[DIGEST_SIZE] = Fp::new(value);
        state[STATE_WIDTH - 1] = Fp::new(DIGEST_SIZE as u64 + 1);

        // apply the Rescue permutation and return the first DIGEST_SIZE elements of the state
        apply_permutation(&mut state);
        Self::Digest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rescue_hash() {
        // Hardcoded input / output list generated from the
        // Sagemath code at https://github.com/KULeuven-COSIC/Marvellous

        let input_data = [
            [Fp::zero(); 7],
            [Fp::one(); 7],
            [
                Fp::new(3781517269054172813),
                Fp::new(2337371443370987581),
                Fp::new(3683636179775925415),
                Fp::new(3924815857507096821),
                Fp::new(323757642230705312),
                Fp::new(562383550419003601),
                Fp::new(898562264908380755),
            ],
            [
                Fp::new(494187647901447079),
                Fp::new(2565024019061861810),
                Fp::new(840620738897402500),
                Fp::new(1584534678763375989),
                Fp::new(4296236333508019208),
                Fp::new(53354413432474292),
                Fp::new(2992492779667716808),
            ],
            [
                Fp::new(3225153378836413963),
                Fp::new(2300749242923206605),
                Fp::new(3847342595614147212),
                Fp::new(4086609254642060164),
                Fp::new(2374900540452086671),
                Fp::new(3790089001244266304),
                Fp::new(125195419613196428),
            ],
            [
                Fp::new(2547249218795028906),
                Fp::new(3315663223227887328),
                Fp::new(4150634392615818407),
                Fp::new(3063462396972696629),
                Fp::new(1732438437243291464),
                Fp::new(3947169041436889086),
                Fp::new(3331191974313148256),
            ],
            [
                Fp::new(4210839745856842156),
                Fp::new(2961655204046525002),
                Fp::new(3925250347272659647),
                Fp::new(588201141250676165),
                Fp::new(1475271927337719246),
                Fp::new(3566527048750580635),
                Fp::new(2497376838139480517),
            ],
            [
                Fp::new(3901825790961456147),
                Fp::new(936241297993374466),
                Fp::new(3370727802467615245),
                Fp::new(1143900608203283610),
                Fp::new(3295999822494349012),
                Fp::new(1006851854631805528),
                Fp::new(2559674882517521518),
            ],
            [
                Fp::new(1707221941547014422),
                Fp::new(3355766467718353408),
                Fp::new(3860842241596693717),
                Fp::new(1384875641172340897),
                Fp::new(2026754972376543189),
                Fp::new(1091568899877398708),
                Fp::new(3314214482741960386),
            ],
            [
                Fp::new(188216236559667914),
                Fp::new(537252142855565928),
                Fp::new(328162280357268543),
                Fp::new(880419078686247957),
                Fp::new(4703913465405241348),
                Fp::new(2937636363852454715),
                Fp::new(530157937763259258),
            ],
            [
                Fp::new(4155568495779165682),
                Fp::new(1214910029704685748),
                Fp::new(2287626346277395613),
                Fp::new(2022923123366804251),
                Fp::new(415550044208279178),
                Fp::new(4556399153636396401),
                Fp::new(4118812954189070011),
            ],
            [
                Fp::new(3707857235909606413),
                Fp::new(2457692780749189573),
                Fp::new(2777043091671652459),
                Fp::new(960894956874852528),
                Fp::new(1510641658388504116),
                Fp::new(2785093824368693159),
                Fp::new(2317497498957355112),
            ],
        ];

        // Generated from https://github.com/KULeuven-COSIC/Marvellous
        let output_data = [
            [
                Fp::new(2498812643529139691),
                Fp::new(3930568995289853285),
                Fp::new(173044719285082093),
                Fp::new(4716608651462919720),
                Fp::new(3451770643957249244),
                Fp::new(3509565116331391584),
                Fp::new(2182292100009095653),
            ],
            [
                Fp::new(550500605462908413),
                Fp::new(1093581068454153090),
                Fp::new(4353530342711757796),
                Fp::new(1610365134479374371),
                Fp::new(3957956355031395439),
                Fp::new(3305392614735604114),
                Fp::new(2429037878288001976),
            ],
            [
                Fp::new(3734331029080437789),
                Fp::new(2338084163058030678),
                Fp::new(900238347273603445),
                Fp::new(1099884636136611870),
                Fp::new(3890496018829630556),
                Fp::new(4708923640773409405),
                Fp::new(896870865634428548),
            ],
            [
                Fp::new(2818163077251726958),
                Fp::new(2770913996258446758),
                Fp::new(4270160537815972384),
                Fp::new(2662276360028203645),
                Fp::new(4717820870545168522),
                Fp::new(1402888426203427848),
                Fp::new(3696612624488572905),
            ],
            [
                Fp::new(700027206569069425),
                Fp::new(3762664502646279185),
                Fp::new(3886037562909593705),
                Fp::new(2573389471334473285),
                Fp::new(4210089597447354282),
                Fp::new(1454173323905027752),
                Fp::new(107629511605904940),
            ],
            [
                Fp::new(1933147893479194035),
                Fp::new(1070025883348947062),
                Fp::new(3162127883295749064),
                Fp::new(4484557139330362402),
                Fp::new(1033514469393444316),
                Fp::new(568779953294157306),
                Fp::new(4626047702423419513),
            ],
            [
                Fp::new(11408951062272352),
                Fp::new(3476485428022774428),
                Fp::new(2889756572478890183),
                Fp::new(3158482189086052480),
                Fp::new(1231105816054410884),
                Fp::new(2039709672297185192),
                Fp::new(2610645956141831329),
            ],
            [
                Fp::new(2421697584177250325),
                Fp::new(1033558199659340537),
                Fp::new(2154906632225207201),
                Fp::new(390692241430719519),
                Fp::new(236217128509651976),
                Fp::new(579775647821121377),
                Fp::new(3160717241658686367),
            ],
            [
                Fp::new(889633502912811635),
                Fp::new(773312816426499593),
                Fp::new(2065161527124058642),
                Fp::new(241445764295855589),
                Fp::new(3831101054982713198),
                Fp::new(1367437393081538225),
                Fp::new(948023406426968155),
            ],
            [
                Fp::new(1825581600027625481),
                Fp::new(1776727800455067583),
                Fp::new(2164491876850946009),
                Fp::new(2340313200674064253),
                Fp::new(998236873040746545),
                Fp::new(251710683774874892),
                Fp::new(2289139457153082703),
            ],
            [
                Fp::new(2785169431054806116),
                Fp::new(4316425227488460484),
                Fp::new(236800147181024914),
                Fp::new(4337813721763069206),
                Fp::new(3741005840547473672),
                Fp::new(1394320078582437796),
                Fp::new(2248280346640137082),
            ],
            [
                Fp::new(2952858514859302306),
                Fp::new(2338070813764417310),
                Fp::new(3124515216882912790),
                Fp::new(4082683324632071309),
                Fp::new(1503551613089216549),
                Fp::new(2587996668303804165),
                Fp::new(3906524165635843728),
            ],
        ];

        for (input, expected) in input_data.iter().zip(output_data) {
            let mut hasher = RescueHash::new();
            hasher.update(input);

            assert_eq!(expected, hasher.finalize().as_elements());
            assert_eq!(expected, RescueHash::digest(input).as_elements());
        }
    }
}
