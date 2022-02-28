// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Hasher trait implementation for Rescue

use core::convert::TryInto;

use super::digest::RescueDigest;
use super::RescuePrimeHasher;
use super::{apply_permutation, DIGEST_SIZE, RATE_WIDTH, STATE_WIDTH};
use crate::error::SerializationError;
use crate::traits::Hasher;

use cheetah::Fp;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// A Rescue Hash over Fp
pub struct RescueHash {
    state: [Fp; STATE_WIDTH],
    idx: usize,
}

impl Default for RescueHash {
    fn default() -> Self {
        Self {
            state: [Fp::zero(); STATE_WIDTH],
            idx: 0,
        }
    }
}

impl RescueHash {
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
    pub fn from_bytes(bytes: &[u8; 120]) -> Result<Self, SerializationError> {
        let mut state = [Fp::zero(); STATE_WIDTH];
        let mut array = [0u8; 8];
        for index in 0..STATE_WIDTH {
            array.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
            let value = Fp::from_bytes(&array);
            state[index] = match value.is_some().into() {
                true => value.unwrap(),
                false => return Err(SerializationError::InvalidFieldElement),
            };
        }

        array.copy_from_slice(&bytes[112..120]);
        let idx = u64::from_le_bytes(array) as usize;

        Ok(Self { state, idx })
    }
}

impl Hasher<Fp> for RescueHash {
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

    fn hash_field(bytes: &[Fp]) -> Self::Digest {
        // initialize state to all zeros
        let mut state = [Fp::zero(); STATE_WIDTH];

        let mut i = 0;
        for &element in bytes.iter() {
            state[i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
            }
        }

        // Apply padding specification from https://eprint.iacr.org/2020/1143.pdf, Algorithm 2
        if i > 0 {
            state[i] += Fp::one();
            i += 1;

            while i % RATE_WIDTH != 0 {
                state[i] += Fp::zero();
                i += 1;
            }

            apply_permutation(&mut state);
        }

        RescueDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = [Fp::zero(); STATE_WIDTH];
        state[..RATE_WIDTH].copy_from_slice(&values[0].as_elements());
        state[RATE_WIDTH..STATE_WIDTH].copy_from_slice(&values[1].as_elements());
        apply_permutation(&mut state);

        RescueDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }
}

impl RescuePrimeHasher<Fp> for RescueHash {
    /// Initializes a new instance of the permutation.
    fn new() -> Self {
        Self::default()
    }

    /// Absorbs a sequence of bytes.
    fn absorb(&mut self, input: &[u8]) {
        // compute the number of elements required to represent the string; we will be processing
        // the string in 7-byte chunks, thus the number of elements will be equal to the number
        // of such chunks (including a potential partial chunk at the end).
        let num_elements = if input.len() % 7 == 0 {
            input.len() / 7
        } else {
            input.len() / 7 + 1
        };

        // break the string into 7-byte chunks, convert each chunk into a field element, and
        // absorb the element into the rate portion of the state. we use 7-byte chunks because
        // every 7-byte chunk is guaranteed to map to some field element.
        let mut num_hashed = 0;
        let mut buf = [0u8; 8];
        for chunk in input.chunks(7) {
            if num_hashed + self.idx < num_elements - 1 {
                buf[..7].copy_from_slice(chunk);
            } else {
                // if we are dealing with the last chunk, it may be smaller than 7 bytes long, so
                // we need to handle it slightly differently. we also append a byte with value 1
                // to the end of the string; this pads the string in such a way that adding
                // trailing zeros results in different hash

                // Compatibility with the binary hash() is not possible because this would require
                // knowing the total input sequence length at initialization, to write in the capacity
                // registers. Hence, we prevent length-extension attacks on every absorbed chunk
                let chunk_len = chunk.len();
                buf = [0u8; 8];
                buf[..chunk_len].copy_from_slice(chunk);
                buf[chunk_len] = 1;
            }

            // convert the bytes into a field element and absorb it into the rate portion of the
            // state; if the rate is filled up, apply the Rescue permutation and start absorbing
            // again from zero index.
            self.state[self.idx] += Fp::new(u64::from_le_bytes(buf));
            self.idx += 1;
            if self.idx % RATE_WIDTH == 0 {
                self.apply_permutation();
                self.idx = 0;
                num_hashed += RATE_WIDTH;
            }
        }
    }

    /// Absorbs a sequence of field elements.
    fn absorb_field(&mut self, input: &[Fp]) {
        for &element in input {
            self.state[self.idx] += element;
            self.idx += 1;
            if self.idx % RATE_WIDTH == 0 {
                self.apply_permutation();
                self.idx = 0;
            }
        }
    }

    /// Applies Rescue-XLIX permutation to the provided state.
    fn apply_permutation(&mut self) {
        apply_permutation(&mut self.state);
    }

    /// Returns hash of the data absorbed into the hasher.
    fn finalize(&mut self) -> Self::Digest {
        // Apply padding specification from https://eprint.iacr.org/2020/1143.pdf, Algorithm 2
        if self.idx > 0 {
            self.state[self.idx] += Fp::one();
            self.idx += 1;

            while self.idx % RATE_WIDTH != 0 {
                self.state[self.idx] += Fp::zero();
                self.idx += 1;
            }

            self.apply_permutation();
            self.idx = 0;
        }

        RescueDigest::new(self.state[..DIGEST_SIZE].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_rescue_hash() {
        // Hardcoded input / output list generated from the
        // Sagemath code at https://github.com/KULeuven-COSIC/Marvellous

        let input_data = [
            [Fp::zero(); 7],
            [Fp::one(); 7],
            [
                Fp::new(3950023656837154780),
                Fp::new(2881042141171700070),
                Fp::new(10779783730324926223),
                Fp::new(2193245569390396079),
                Fp::new(16253948482548340315),
                Fp::new(1218876753142647280),
                Fp::new(4665677124148004089),
            ],
            [
                Fp::new(15510680881292026648),
                Fp::new(1885599458732076372),
                Fp::new(3009832769468343331),
                Fp::new(4278715578773017787),
                Fp::new(1527318565755464029),
                Fp::new(15305488897400747380),
                Fp::new(16465990826098742194),
            ],
            [
                Fp::new(140365944095159147),
                Fp::new(15974833700665793655),
                Fp::new(4537294998186101657),
                Fp::new(5109852931603194239),
                Fp::new(17928282694277838009),
                Fp::new(13253300241959402999),
                Fp::new(3823973534601399165),
            ],
            [
                Fp::new(17954336847934734809),
                Fp::new(12987799873114840312),
                Fp::new(12918391975014059030),
                Fp::new(13534406757215195217),
                Fp::new(7015568714821117231),
                Fp::new(16406332556186741701),
                Fp::new(13841094173526572577),
            ],
            [
                Fp::new(5639224153506147889),
                Fp::new(11045864791932293505),
                Fp::new(16971439160821907715),
                Fp::new(11823824893550570395),
                Fp::new(6530760332296797048),
                Fp::new(16658398244005217282),
                Fp::new(17596930911850813020),
            ],
            [
                Fp::new(14177301956587338153),
                Fp::new(11152794082924817567),
                Fp::new(6237926186494600489),
                Fp::new(2860546146811461105),
                Fp::new(1945982128333621329),
                Fp::new(16175721111896472344),
                Fp::new(12470940840517216660),
            ],
            [
                Fp::new(4108451947597787380),
                Fp::new(17716249113802510600),
                Fp::new(2842886041996649217),
                Fp::new(3125385885849793569),
                Fp::new(14222444035786103231),
                Fp::new(14291592125380804622),
                Fp::new(15788476122562488600),
            ],
            [
                Fp::new(6324039691650518534),
                Fp::new(4854235111930838947),
                Fp::new(9528543306599103227),
                Fp::new(1908154389856780779),
                Fp::new(725275410145065933),
                Fp::new(2994053441956803602),
                Fp::new(14870768704779351904),
            ],
            [
                Fp::new(16708718752419310323),
                Fp::new(9043524975036485217),
                Fp::new(10559977491562365190),
                Fp::new(10805193695687328688),
                Fp::new(3342433955286461953),
                Fp::new(6763271737144514490),
                Fp::new(8128474802178971483),
            ],
            [
                Fp::new(14371251217142520515),
                Fp::new(4338524858237943279),
                Fp::new(17283938505215119784),
                Fp::new(18443919525318776756),
                Fp::new(11554353940375106506),
                Fp::new(9935875077770851674),
                Fp::new(16651331719620526423),
            ],
        ];

        // Generated from https://github.com/KULeuven-COSIC/Marvellous
        let output_data = [
            [
                Fp::new(1462852121402184757),
                Fp::new(3851389896230401122),
                Fp::new(5882996393075625557),
                Fp::new(10521291612941708615),
                Fp::new(17822059276976522025),
                Fp::new(6442736186431050368),
                Fp::new(13017287424191436946),
            ],
            [
                Fp::new(2775776797579705596),
                Fp::new(2403614533261838082),
                Fp::new(7693169250485223950),
                Fp::new(11055303056864038887),
                Fp::new(7628852160479342589),
                Fp::new(12233463306084900855),
                Fp::new(11936639582709302076),
            ],
            [
                Fp::new(11505824700477102572),
                Fp::new(16374638205843913216),
                Fp::new(4248359725379407058),
                Fp::new(6377440333976445055),
                Fp::new(12153834900075533870),
                Fp::new(16552688606391487587),
                Fp::new(13487106855369955288),
            ],
            [
                Fp::new(16831576602944861321),
                Fp::new(10554228133044132029),
                Fp::new(7341467356168262539),
                Fp::new(18048235872609925908),
                Fp::new(15349705420822053264),
                Fp::new(5099126063801993907),
                Fp::new(15758960528207547734),
            ],
            [
                Fp::new(6140546130285181457),
                Fp::new(9717430031239952053),
                Fp::new(426384473071363511),
                Fp::new(8738424094168606662),
                Fp::new(13895934231411749553),
                Fp::new(9745694210096996441),
                Fp::new(238205385641180480),
            ],
            [
                Fp::new(12072258341513292338),
                Fp::new(1653787536644408066),
                Fp::new(2553325559739182980),
                Fp::new(14494640366770314229),
                Fp::new(6632328271058782797),
                Fp::new(17136655182521628181),
                Fp::new(9648599993263888708),
            ],
            [
                Fp::new(16172310988415901282),
                Fp::new(3867868964145925742),
                Fp::new(16640854393851664160),
                Fp::new(13380412620490202361),
                Fp::new(9755980514321283475),
                Fp::new(17079300832339333147),
                Fp::new(3148591176626069201),
            ],
            [
                Fp::new(5495083559674337780),
                Fp::new(12519343593850221554),
                Fp::new(14454522298770281509),
                Fp::new(7282539795336546358),
                Fp::new(12637748394059553436),
                Fp::new(3660318624754655797),
                Fp::new(16464209702200801348),
            ],
            [
                Fp::new(561228919855163821),
                Fp::new(5745477782921558501),
                Fp::new(14345931443850607969),
                Fp::new(10911934545965820926),
                Fp::new(11564909789117272275),
                Fp::new(6575963491016418381),
                Fp::new(6688464136460516678),
            ],
            [
                Fp::new(5430170233120162060),
                Fp::new(14073448356996281917),
                Fp::new(9529268804005242596),
                Fp::new(15835814726539502651),
                Fp::new(18114992307639882028),
                Fp::new(13124714119438319363),
                Fp::new(17208402121800201187),
            ],
            [
                Fp::new(502659996860556413),
                Fp::new(7249969696684244242),
                Fp::new(3655199103889939873),
                Fp::new(6630626149995182382),
                Fp::new(7831937114322467287),
                Fp::new(4499093287722173119),
                Fp::new(360388548637633151),
            ],
            [
                Fp::new(9679775309692013648),
                Fp::new(14664355940396898404),
                Fp::new(10840083312362647488),
                Fp::new(10643787539329357191),
                Fp::new(4579477574868391271),
                Fp::new(7919466403874804166),
                Fp::new(549103385692248750),
            ],
        ];

        for (input, expected) in input_data.iter().zip(output_data) {
            let mut hasher = RescueHash::new();
            hasher.absorb_field(input);

            assert_eq!(expected, hasher.finalize().as_elements());
            assert_eq!(expected, RescueHash::hash_field(input).as_elements());
        }
    }

    #[test]
    fn test_sequential_hashing() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let mut data = [Fp::zero(); 100];
            for e in data.iter_mut() {
                *e = Fp::random(&mut rng);
            }

            let mut hasher = RescueHash::new();
            for chunk in data.chunks(10) {
                hasher.absorb_field(chunk);
            }

            assert_eq!(hasher.finalize(), RescueHash::hash_field(&data));
        }
    }

    #[test]
    fn test_serialization() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let mut data = [Fp::zero(); DIGEST_SIZE];
            for e in data.iter_mut() {
                *e = Fp::random(&mut rng);
            }

            let mut hasher = RescueHash::new();
            hasher.absorb_field(&data);

            let bytes = hasher.to_bytes();

            assert_eq!(hasher, RescueHash::from_bytes(&bytes).unwrap());
        }

        // Test invalid encoding
        let mut data = [Fp::zero(); DIGEST_SIZE];
        for e in data.iter_mut() {
            *e = Fp::random(&mut rng);
        }

        let mut hasher = RescueHash::new();
        hasher.absorb_field(&data);

        let bytes = [255u8; 120];

        assert!(RescueHash::from_bytes(&bytes).is_err());
    }
}
