// Copyright (c) 2021-2023 Toposware, Inc.
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
    pub fn to_bytes(&self) -> [u8; 104] {
        let mut res = [0u8; 104];
        assert_eq!(res.len(), STATE_WIDTH * 8 + 8);

        for (index, elem) in self.state.iter().enumerate() {
            res[index * 8..index * 8 + 8].copy_from_slice(&elem.to_bytes());
        }
        res[96..104].copy_from_slice(&(self.idx as u64).to_le_bytes());

        res
    }

    /// Returns a RescueHash from an array of bytes
    pub fn from_bytes(bytes: &[u8; 104]) -> Result<Self, SerializationError> {
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

        array.copy_from_slice(&bytes[96..104]);
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
                state[i] = Fp::zero();
                i += 1;
            }

            apply_permutation(&mut state);
        }

        RescueDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = [Fp::zero(); STATE_WIDTH];
        state[..DIGEST_SIZE].copy_from_slice(values[0].as_elements());
        state[DIGEST_SIZE..RATE_WIDTH].copy_from_slice(values[1].as_elements());
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
                apply_permutation(&mut self.state);
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
                apply_permutation(&mut self.state);
                self.idx = 0;
            }
        }
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

            apply_permutation(&mut self.state);
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
            [Fp::zero(); 8],
            [Fp::one(); 8],
            [
                Fp::new(7530915893948438626),
                Fp::new(8800061101499087155),
                Fp::new(12743810843683093000),
                Fp::new(4628143886977575438),
                Fp::new(16155374671114756449),
                Fp::new(225681431990641162),
                Fp::new(3305860315173298679),
                Fp::new(12303317461071026747),
            ],
            [
                Fp::new(9232740412975669615),
                Fp::new(9217116013228601478),
                Fp::new(4293830967808188456),
                Fp::new(15456182631886251678),
                Fp::new(3618766818863880191),
                Fp::new(6280935809956460128),
                Fp::new(7166666823015080026),
                Fp::new(15302134487432567685),
            ],
            [
                Fp::new(8976450671476087579),
                Fp::new(5206208508610893389),
                Fp::new(12271224547228316131),
                Fp::new(14562169154073895878),
                Fp::new(18381637277455387460),
                Fp::new(2224570723939504398),
                Fp::new(7905616110921470821),
                Fp::new(15810140845034840589),
            ],
            [
                Fp::new(14703595238443130817),
                Fp::new(12269863200642762253),
                Fp::new(13309074902582409385),
                Fp::new(11451252427570209184),
                Fp::new(13949002048085204773),
                Fp::new(3506016914581130862),
                Fp::new(8294829337045451114),
                Fp::new(14730089488118988067),
            ],
            [
                Fp::new(13727543658444052614),
                Fp::new(3301731079042393535),
                Fp::new(8773684773487387580),
                Fp::new(12457097156282238046),
                Fp::new(4773227697638147630),
                Fp::new(3041578054038681607),
                Fp::new(14910324427389276793),
                Fp::new(17119171213850456798),
            ],
            [
                Fp::new(7051595418337823791),
                Fp::new(11061065355704098278),
                Fp::new(7769052988784367659),
                Fp::new(11464517154732981339),
                Fp::new(11860578015795370951),
                Fp::new(6482118144004227366),
                Fp::new(2643075426059191149),
                Fp::new(10845980447339616669),
            ],
            [
                Fp::new(3739407871605716475),
                Fp::new(9932405777274885080),
                Fp::new(1036973164224876505),
                Fp::new(8847574931823078112),
                Fp::new(16331651222792910346),
                Fp::new(1409516521885489804),
                Fp::new(12498791972854057381),
                Fp::new(13213095980122521460),
            ],
            [
                Fp::new(15948280688979628003),
                Fp::new(4542759336325540548),
                Fp::new(10423869491311504304),
                Fp::new(6116965229813709897),
                Fp::new(9997452706318235316),
                Fp::new(12234278137845288153),
                Fp::new(11331574913163666769),
                Fp::new(6716575775176135507),
            ],
            [
                Fp::new(17343255975828003173),
                Fp::new(6841835512675325978),
                Fp::new(3178096146976164032),
                Fp::new(6827999881416465630),
                Fp::new(408991702186327027),
                Fp::new(13945938860465172083),
                Fp::new(11199243469254684516),
                Fp::new(2364947769764614259),
            ],
            [
                Fp::new(16866739842298834481),
                Fp::new(15804104725181108095),
                Fp::new(16235277953650691713),
                Fp::new(2380130476509117239),
                Fp::new(2486067328955017838),
                Fp::new(114713685744251284),
                Fp::new(16291208580772733813),
                Fp::new(13085537500555952616),
            ],
        ];

        // Generated from https://github.com/KULeuven-COSIC/Marvellous
        let output_data = [
            [
                Fp::new(8957274432841348180),
                Fp::new(3462715397810997323),
                Fp::new(9112765074729698987),
                Fp::new(11355028649842365827),
            ],
            [
                Fp::new(16860573314894026072),
                Fp::new(5223843823279297510),
                Fp::new(17146077934831331816),
                Fp::new(1076129696200382409),
            ],
            [
                Fp::new(385451156385315105),
                Fp::new(11994038392662145018),
                Fp::new(7632024281529462977),
                Fp::new(5317415691698369519),
            ],
            [
                Fp::new(7634219720733306056),
                Fp::new(6889289224278063501),
                Fp::new(3463611688492982199),
                Fp::new(12243541559173475734),
            ],
            [
                Fp::new(12910778150988268406),
                Fp::new(6721677852547751722),
                Fp::new(15338667631621161111),
                Fp::new(3349511616106826986),
            ],
            [
                Fp::new(14074513124259758560),
                Fp::new(10576045581525278514),
                Fp::new(17596596104494687104),
                Fp::new(9631486794090898638),
            ],
            [
                Fp::new(14255128892540666349),
                Fp::new(14035587348265876394),
                Fp::new(3245911794536653629),
                Fp::new(7140385534664095817),
            ],
            [
                Fp::new(14314174965950323374),
                Fp::new(4276965885099153937),
                Fp::new(2275243438436362800),
                Fp::new(7252573281430515362),
            ],
            [
                Fp::new(5209700993096539928),
                Fp::new(6089625723753540745),
                Fp::new(6297390213497306087),
                Fp::new(4509897997873590055),
            ],
            [
                Fp::new(16375031809269366825),
                Fp::new(1975494321099680522),
                Fp::new(16172742695858153202),
                Fp::new(12794730112675404054),
            ],
            [
                Fp::new(3565792055342030874),
                Fp::new(5739572764667266160),
                Fp::new(9803656867053797995),
                Fp::new(14218697028597755720),
            ],
            [
                Fp::new(5167820285577335236),
                Fp::new(9477824282780185416),
                Fp::new(6769847770881182012),
                Fp::new(809373104972971964),
            ],
        ];

        for (input, expected) in input_data.iter().zip(output_data) {
            let mut hasher = RescueHash::new();
            hasher.absorb_field(input);

            assert_eq!(expected, hasher.finalize().to_elements());
            assert_eq!(expected, RescueHash::hash_field(input).to_elements());
        }
    }

    #[test]
    fn test_sequential_hashing() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let mut data = [Fp::zero(); 160];
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

        let bytes = [255u8; 104];

        assert!(RescueHash::from_bytes(&bytes).is_err());
    }
}
