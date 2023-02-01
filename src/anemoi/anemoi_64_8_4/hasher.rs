// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Hasher trait implementation for Anemoi

use core::convert::TryInto;

use super::digest::AnemoiDigest;
use super::AnemoiHasher;
use super::AnemoiJive;
use super::{apply_permutation, DIGEST_SIZE, NUM_COLUMNS, RATE_WIDTH, STATE_WIDTH};
use crate::error::SerializationError;
use crate::traits::Hasher;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use cheetah::Fp;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// A Anemoi Hash over Fp
pub struct AnemoiHash {
    state: [Fp; STATE_WIDTH],
    idx: usize,
}

impl Default for AnemoiHash {
    fn default() -> Self {
        Self {
            state: [Fp::zero(); STATE_WIDTH],
            idx: 0,
        }
    }
}

impl AnemoiHash {
    /// Serializes the current state to an array of bytes
    pub fn to_bytes(&self) -> [u8; 72] {
        let mut res = [0u8; 72];
        assert_eq!(res.len(), STATE_WIDTH * 8 + 8);

        for (index, elem) in self.state.iter().enumerate() {
            res[index * 8..index * 8 + 8].copy_from_slice(&elem.to_bytes());
        }
        res[64..72].copy_from_slice(&(self.idx as u64).to_le_bytes());

        res
    }

    /// Returns a AnemoiHash from an array of bytes
    pub fn from_bytes(bytes: &[u8; 72]) -> Result<Self, SerializationError> {
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

        array.copy_from_slice(&bytes[64..72]);
        let idx = u64::from_le_bytes(array) as usize;

        Ok(Self { state, idx })
    }
}

impl Hasher<Fp> for AnemoiHash {
    type Digest = AnemoiDigest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // compute the number of elements required to represent the string; we will be processing
        // the string in 7-byte chunks, thus the number of elements will be equal to the number
        // of such chunks (including a potential partial chunk at the end).
        let num_elements = if bytes.len() % 7 == 0 {
            bytes.len() / 7
        } else {
            bytes.len() / 7 + 1
        };

        let sigma = if num_elements % RATE_WIDTH == 0 {
            Fp::one()
        } else {
            Fp::zero()
        };

        // initialize state to all zeros.
        let mut state = [Fp::zero(); STATE_WIDTH];

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
                // we need to handle it slightly differently. We also append a byte with value 1
                // to the end of the string; this pads the string in such a way that adding
                // trailing zeros results in a different hash.

                // Compatibility with the hash_field() method is not possible because this would require
                // knowing the total input sequence length at initialization, to write in the capacity
                // registers. Instead, we prevent length-extension attacks on every absorbed input slice.
                let chunk_len = chunk.len();
                buf = [0u8; 8];
                buf[..chunk_len].copy_from_slice(chunk);
                buf[chunk_len] = 1;
            }

            // convert the bytes into a field element and absorb it into the rate portion of the
            // state; if the rate is filled up, apply the Anemoi permutation and start absorbing
            // again from zero index.
            state[i] += Fp::new(u64::from_le_bytes(buf));
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
                num_hashed += RATE_WIDTH;
            }
        }

        // We then add sigma to the last capacity register of the capacity.
        state[STATE_WIDTH - 1] += sigma;

        // If the message length is not a multiple of RATE_WIDTH, we append 1 to the rate cell
        // next to the one where we previously appended the last message element. This is
        // guaranted to be in the rate registers (i.e. to not require an extra permutation before
        // adding this constant) if sigma is equal to zero.
        if sigma.is_zero().into() {
            state[i] += Fp::one();
        }

        // return the first DIGEST_SIZE elements of the state as hash result
        AnemoiDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn hash_field(bytes: &[Fp]) -> Self::Digest {
        // initialize state to all zeros.
        let mut state = [Fp::zero(); STATE_WIDTH];

        let sigma = if bytes.len() % RATE_WIDTH == 0 {
            Fp::one()
        } else {
            Fp::zero()
        };

        let mut i = 0;
        for &element in bytes.iter() {
            state[i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
            }
        }

        // If the message length is not a multiple of RATE_WIDTH, we append 1 to the rate cell
        // next to the one where we previously appended the last message element. This is
        // guaranted to be in the rate registers (i.e. to not require an extra permutation before
        // adding this constant) if sigma is equal to zero.
        if sigma.is_zero().into() {
            state[i] += Fp::one();
            apply_permutation(&mut state);
        }

        // We then add sigma to the last capacity register of the capacity.
        state[STATE_WIDTH - 1] += sigma;

        AnemoiDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    // This merge function uses the compression approach of Anemoi-Jive
    // to save one Anemoi permutation call , which would be necessary if
    // using the regular Anemoi-Sponge to absorb two digests, both of
    // size RATE_WIDTH.
    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = [Fp::zero(); STATE_WIDTH];
        let digest1 = values[0].as_elements();
        let digest2 = values[1].as_elements();
        state[..RATE_WIDTH].copy_from_slice(digest1);
        state[RATE_WIDTH..STATE_WIDTH].copy_from_slice(digest2);
        apply_permutation(&mut state);

        let mut result = [Fp::zero(); DIGEST_SIZE];
        for (i, r) in result.iter_mut().enumerate() {
            *r = digest1[i] + digest2[i] + state[i] + state[i + NUM_COLUMNS];
        }

        AnemoiDigest::new(result)
    }
}

impl AnemoiHasher<Fp> for AnemoiHash {
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
            // state; if the rate is filled up, apply the Anemoi permutation and start absorbing
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
        // Apply padding specification
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

        AnemoiDigest::new(self.state[..DIGEST_SIZE].try_into().unwrap())
    }
}

impl AnemoiJive<Fp> for AnemoiHash {
    fn compress(elems: &[Fp]) -> Vec<Fp> {
        assert!(elems.len() == STATE_WIDTH);

        let mut state = elems.try_into().unwrap();
        apply_permutation(&mut state);

        let mut result = [Fp::zero(); NUM_COLUMNS];
        for (i, r) in result.iter_mut().enumerate() {
            *r = elems[i] + elems[i + NUM_COLUMNS] + state[i] + state[i + NUM_COLUMNS];
        }

        result.to_vec()
    }

    fn compress_k(elems: &[Fp], k: usize) -> Vec<Fp> {
        // We can output as few as 4 elements while
        // maintaining the targeted security level.
        assert!(k == 2);

        Self::compress(elems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_anemoi_hash() {
        // Hardcoded input / output list generated from the
        // Sagemath code at https://github.com/Nashtare/anemoi-hash/

        let input_data = [
            vec![Fp::zero(); 8],
            vec![Fp::one(); 8],
            vec![
                Fp::zero(),
                Fp::zero(),
                Fp::zero(),
                Fp::zero(),
                Fp::one(),
                Fp::one(),
                Fp::one(),
                Fp::one(),
            ],
            vec![
                Fp::one(),
                Fp::one(),
                Fp::one(),
                Fp::one(),
                Fp::zero(),
                Fp::zero(),
                Fp::zero(),
                Fp::zero(),
            ],
            vec![Fp::new(17034304680378990593)],
            vec![Fp::new(14717522243836148645), Fp::new(13083744320516212099)],
            vec![
                Fp::new(12636374470493764585),
                Fp::new(4633685103624134705),
                Fp::new(3387113220078373436),
            ],
            vec![
                Fp::new(8456646190515084682),
                Fp::new(13422660296625058046),
                Fp::new(6412264356237719015),
                Fp::new(15681324668660747245),
            ],
            vec![
                Fp::new(5024098825481674854),
                Fp::new(17074804226935063103),
                Fp::new(12706716815026291874),
                Fp::new(15111404609115389377),
                Fp::new(14660803971611056841),
            ],
            vec![
                Fp::new(12593193490016384806),
                Fp::new(18163695353480745896),
                Fp::new(12379842404544411425),
                Fp::new(15341182951106044393),
                Fp::new(1499922380158571885),
                Fp::new(4387632416457430195),
            ],
        ];

        let output_data = [
            [
                Fp::new(163801914873424873),
                Fp::new(1975920130069291731),
                Fp::new(11347519605622270163),
                Fp::new(13645969218783075933),
            ],
            [
                Fp::new(10146598142737807481),
                Fp::new(16567096201507333296),
                Fp::new(17955106716319642741),
                Fp::new(4860486773238898208),
            ],
            [
                Fp::new(6111781501637081646),
                Fp::new(10187415424684290095),
                Fp::new(17663585034052564413),
                Fp::new(1533771651848622457),
            ],
            [
                Fp::new(6882943066109610085),
                Fp::new(18116611745108827517),
                Fp::new(10320885853741934988),
                Fp::new(851003075264447500),
            ],
            [
                Fp::new(9937678481006433665),
                Fp::new(5613531991639406668),
                Fp::new(826203708134430950),
                Fp::new(5856376835295707176),
            ],
            [
                Fp::new(12354948106612827967),
                Fp::new(18225731063279096760),
                Fp::new(12692549507758853073),
                Fp::new(5857129691129105835),
            ],
            [
                Fp::new(17178281612961548790),
                Fp::new(15592307425962170877),
                Fp::new(3291082425520566106),
                Fp::new(1457588681846648616),
            ],
            [
                Fp::new(3831087655484288576),
                Fp::new(1529151277776990392),
                Fp::new(18237347415792447921),
                Fp::new(2518543518700876920),
            ],
            [
                Fp::new(39132530386866452),
                Fp::new(12435901606157783280),
                Fp::new(16259807811311764920),
                Fp::new(13912323646801342253),
            ],
            [
                Fp::new(12397702082065942083),
                Fp::new(15528997894970156290),
                Fp::new(7340685217165164207),
                Fp::new(12732717666166972168),
            ],
        ];

        for (input, expected) in input_data.iter().zip(output_data) {
            assert_eq!(expected, AnemoiHash::hash_field(input).to_elements());
        }
    }

    #[test]
    fn test_anemoi_jive() {
        // Hardcoded input / output list generated from the
        // Sagemath code at https://github.com/Nashtare/anemoi-hash/

        let input_data = [
            vec![Fp::zero(); 8],
            vec![Fp::one(); 8],
            vec![
                Fp::zero(),
                Fp::zero(),
                Fp::zero(),
                Fp::zero(),
                Fp::one(),
                Fp::one(),
                Fp::one(),
                Fp::one(),
            ],
            vec![
                Fp::one(),
                Fp::one(),
                Fp::one(),
                Fp::one(),
                Fp::zero(),
                Fp::zero(),
                Fp::zero(),
                Fp::zero(),
            ],
            vec![
                Fp::new(6864100358698396972),
                Fp::new(9852648706634602938),
                Fp::new(17299604986243836005),
                Fp::new(2967959179556219487),
                Fp::new(5587008257663068368),
                Fp::new(16076206809461091550),
                Fp::new(5680034992135401507),
                Fp::new(16925010989173816363),
            ],
            vec![
                Fp::new(9237841405951070761),
                Fp::new(4147419961602069409),
                Fp::new(12675694838131447342),
                Fp::new(17473285044120526663),
                Fp::new(15660863388600731400),
                Fp::new(18159026123990989104),
                Fp::new(7388206688290894678),
                Fp::new(10198998282728399193),
            ],
            vec![
                Fp::new(15361553562599249381),
                Fp::new(5325622272346395893),
                Fp::new(1796191056064015009),
                Fp::new(17621219096327647240),
                Fp::new(11339403584673697106),
                Fp::new(15479494374155546618),
                Fp::new(14392135274702200738),
                Fp::new(10768898963138974812),
            ],
            vec![
                Fp::new(1791829227709510077),
                Fp::new(2215375202435463925),
                Fp::new(15594475566156739459),
                Fp::new(7354253692809248468),
                Fp::new(13657225050984993705),
                Fp::new(9692784164764834170),
                Fp::new(12281533845677789384),
                Fp::new(8229210346033709985),
            ],
            vec![
                Fp::new(7569316372170859629),
                Fp::new(7488445148635950080),
                Fp::new(1854425811737470374),
                Fp::new(7824497847624546217),
                Fp::new(9109115638624398924),
                Fp::new(13455637942225211849),
                Fp::new(8005531196680528762),
                Fp::new(4840738537098560964),
            ],
            vec![
                Fp::new(11333156792614692662),
                Fp::new(744678176495995831),
                Fp::new(11844230214129286446),
                Fp::new(18425146562436827676),
                Fp::new(2667704039790742301),
                Fp::new(2536861409698875125),
                Fp::new(11109105022578906087),
                Fp::new(7710859971872283733),
            ],
        ];

        let output_data = [
            [
                Fp::new(17445080680277672729),
                Fp::new(15279244978827238954),
                Fp::new(11164648585654439034),
                Fp::new(16895974665666658381),
            ],
            [
                Fp::new(10897301215636111136),
                Fp::new(17383742727130619928),
                Fp::new(15155208209241471474),
                Fp::new(8201026268903060889),
            ],
            [
                Fp::new(11031296853518254624),
                Fp::new(17156937295482392572),
                Fp::new(17349867163563273629),
                Fp::new(3020353016813562496),
            ],
            [
                Fp::new(17531807959695973699),
                Fp::new(13546054845639752335),
                Fp::new(10130167481231388312),
                Fp::new(6753824039222271515),
            ],
            [
                Fp::new(3508188307333281419),
                Fp::new(7509684582368593749),
                Fp::new(15205365718481105920),
                Fp::new(354469648951776642),
            ],
            [
                Fp::new(17348904869175405833),
                Fp::new(7831905332138861333),
                Fp::new(7413967960496138290),
                Fp::new(7994189113947399247),
            ],
            [
                Fp::new(438167101729894988),
                Fp::new(9458556989031776830),
                Fp::new(11550685638821495398),
                Fp::new(9458349257261883172),
            ],
            [
                Fp::new(1385227500273511876),
                Fp::new(13794266024679291577),
                Fp::new(9584187814469207833),
                Fp::new(6640980482624319287),
            ],
            [
                Fp::new(10381792525717242613),
                Fp::new(15637428335134660854),
                Fp::new(7133307737544842575),
                Fp::new(4462936807575725996),
            ],
            [
                Fp::new(1984527682475092436),
                Fp::new(16242937433469814673),
                Fp::new(13770813404256448923),
                Fp::new(4364947952854271806),
            ],
        ];

        for (input, expected) in input_data.iter().zip(output_data) {
            assert_eq!(expected.to_vec(), AnemoiHash::compress(input));
        }

        for (input, expected) in input_data.iter().zip(output_data) {
            assert_eq!(expected.to_vec(), AnemoiHash::compress_k(input, 2));
        }
    }

    #[test]
    fn test_sequential_hashing() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let mut data = [Fp::zero(); 120];
            for e in data.iter_mut() {
                *e = Fp::random(&mut rng);
            }

            let mut hasher = AnemoiHash::new();
            for chunk in data.chunks(4) {
                hasher.absorb_field(chunk);
            }

            assert_eq!(hasher.finalize(), AnemoiHash::hash_field(&data));
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

            let mut hasher = AnemoiHash::new();
            hasher.absorb_field(&data);

            let bytes = hasher.to_bytes();

            assert_eq!(hasher, AnemoiHash::from_bytes(&bytes).unwrap());
        }

        // Test invalid encoding
        let mut data = [Fp::zero(); DIGEST_SIZE];
        for e in data.iter_mut() {
            *e = Fp::random(&mut rng);
        }

        let mut hasher = AnemoiHash::new();
        hasher.absorb_field(&data);

        let bytes = [255u8; 72];

        assert!(AnemoiHash::from_bytes(&bytes).is_err());
    }
}
