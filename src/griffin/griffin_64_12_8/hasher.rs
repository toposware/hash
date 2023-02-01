// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Hasher trait implementation for Griffin

use core::convert::TryInto;

use super::digest::GriffinDigest;
use super::{apply_permutation, DIGEST_SIZE, RATE_WIDTH, STATE_WIDTH};
use crate::traits::Hasher;

use cheetah::Fp;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// A Griffin Hash over Fp
pub struct GriffinHash {
    state: [Fp; STATE_WIDTH],
    idx: usize,
}

impl Default for GriffinHash {
    fn default() -> Self {
        Self {
            state: [Fp::zero(); STATE_WIDTH],
            idx: 0,
        }
    }
}

impl Hasher<Fp> for GriffinHash {
    type Digest = GriffinDigest;

    fn hash(bytes: &[Fp]) -> Self::Digest {
        // initialize state to all zeros, except for the first element of the capacity part, which
        // is set to 1 conditionally on the input length. this is done so that adding zero elements
        // at the end of the list always results in a different hash.
        let mut state = [Fp::zero(); STATE_WIDTH];
        if bytes.len() % RATE_WIDTH != 0 {
            state[RATE_WIDTH] = Fp::one();
        }

        let mut i = 0;
        for &element in bytes.iter() {
            state[i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
            }
        }

        if i > 0 {
            state[i] += Fp::one();
            apply_permutation(&mut state);
        }

        GriffinDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = [Fp::zero(); STATE_WIDTH];
        state[..DIGEST_SIZE].copy_from_slice(values[0].as_elements());
        state[DIGEST_SIZE..RATE_WIDTH].copy_from_slice(values[1].as_elements());
        apply_permutation(&mut state);

        GriffinDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_griffin_hash() {
        // Hardcoded input / output list generated from the
        // Sagemath code at https://github.com/Nashtare/griffin-hash/tree/vanilla

        let input_data = [
            [Fp::zero(); 8],
            [Fp::one(); 8],
            [
                Fp::new(143835656445250532),
                Fp::new(8588945589064217246),
                Fp::new(14914925262525905064),
                Fp::new(10241362817062963277),
                Fp::new(7338743284255478632),
                Fp::new(11963425003769971228),
                Fp::new(12772390776206626904),
                Fp::new(5552191608305450455),
            ],
            [
                Fp::new(7550977972904333281),
                Fp::new(11869616307609901246),
                Fp::new(5467317284413202612),
                Fp::new(1194095608054288582),
                Fp::new(6934283981703903139),
                Fp::new(14067626850988062280),
                Fp::new(18191131914356578446),
                Fp::new(6074403290104095486),
            ],
            [
                Fp::new(15146140513243670348),
                Fp::new(14809479514295488968),
                Fp::new(17797475118126693063),
                Fp::new(1499918266038777218),
                Fp::new(16281840470678856750),
                Fp::new(9368824957753765048),
                Fp::new(8813483230224475745),
                Fp::new(14774041843158260516),
            ],
            [
                Fp::new(3454811229912402715),
                Fp::new(2086750791464957063),
                Fp::new(13782330347843746217),
                Fp::new(12122529766317503532),
                Fp::new(3728248861897745398),
                Fp::new(537826549464690308),
                Fp::new(6710729548982170456),
                Fp::new(171585277549949255),
            ],
            [
                Fp::new(15858493714949280015),
                Fp::new(9793040650392619728),
                Fp::new(11077747294264606449),
                Fp::new(13015444224781403623),
                Fp::new(10615438807730049512),
                Fp::new(2917202005763106505),
                Fp::new(4434938248091354485),
                Fp::new(4582780333798242121),
            ],
            [
                Fp::new(1466351791110873546),
                Fp::new(17919482528528992688),
                Fp::new(15580672150862546995),
                Fp::new(13509686673724911394),
                Fp::new(14125726116442832651),
                Fp::new(13554710009423192928),
                Fp::new(5646199708290708597),
                Fp::new(14965543528249235409),
            ],
            [
                Fp::new(14451493439179004078),
                Fp::new(10342833705552205206),
                Fp::new(4316887804930711763),
                Fp::new(10175016480521367626),
                Fp::new(16788463717923100855),
                Fp::new(933239300317040227),
                Fp::new(825282628975782785),
                Fp::new(6542016149649311138),
            ],
            [
                Fp::new(1544859024974749034),
                Fp::new(11949779656009368392),
                Fp::new(2264704631238959574),
                Fp::new(8086551323959354142),
                Fp::new(10934086189883333470),
                Fp::new(11519787409121034329),
                Fp::new(6770820725869374837),
                Fp::new(466291762996696457),
            ],
            [
                Fp::new(2012180497780215899),
                Fp::new(13288388624410969622),
                Fp::new(13864066192155676861),
                Fp::new(13610400247862913058),
                Fp::new(14705173282000473796),
                Fp::new(1105728855832400759),
                Fp::new(14323545979787795415),
                Fp::new(13661265567195680017),
            ],
            [
                Fp::new(14951084174590887270),
                Fp::new(18168054934828318390),
                Fp::new(8486847222800219891),
                Fp::new(13271398574769974481),
                Fp::new(16489405039245877971),
                Fp::new(14495531841647303298),
                Fp::new(13720485433206042602),
                Fp::new(11228336358994613506),
            ],
        ];

        // Generated from https://github.com/Nashtare/griffin-hash/tree/vanilla
        let output_data = [
            [
                Fp::new(17968308944347041943),
                Fp::new(11323963566022366783),
                Fp::new(2785880935589291308),
                Fp::new(12630011860428971983),
            ],
            [
                Fp::new(7832771548257351644),
                Fp::new(11845531751518234968),
                Fp::new(2510178833924210161),
                Fp::new(6286536268675410788),
            ],
            [
                Fp::new(5210411351194033278),
                Fp::new(14977282768170357812),
                Fp::new(5005495228444803867),
                Fp::new(5729211741175946619),
            ],
            [
                Fp::new(8776173867124817000),
                Fp::new(16849234544464224872),
                Fp::new(6598632929646078459),
                Fp::new(8762593692461697477),
            ],
            [
                Fp::new(17181578027779397680),
                Fp::new(10205181390484706609),
                Fp::new(17578091390793927638),
                Fp::new(11090885906144243668),
            ],
            [
                Fp::new(6955282848289300575),
                Fp::new(12300611939167953426),
                Fp::new(3535160012844714047),
                Fp::new(14778542029518209895),
            ],
            [
                Fp::new(394770063708346447),
                Fp::new(16818039620691739974),
                Fp::new(17430504468784756453),
                Fp::new(4043214769710906245),
            ],
            [
                Fp::new(13594022732661605186),
                Fp::new(10477511385810122160),
                Fp::new(1013579145476999989),
                Fp::new(3609760142269258678),
            ],
            [
                Fp::new(9487021955286464111),
                Fp::new(9890277348265278724),
                Fp::new(8021266109886998369),
                Fp::new(6630969597838630200),
            ],
            [
                Fp::new(4066110771872946977),
                Fp::new(6702899025965483498),
                Fp::new(11886809226030181375),
                Fp::new(6506087467862163433),
            ],
            [
                Fp::new(4219375039922632839),
                Fp::new(7420296828232616431),
                Fp::new(200165686044458651),
                Fp::new(17452094344595829798),
            ],
            [
                Fp::new(16367441615663991650),
                Fp::new(1245212801735704426),
                Fp::new(2942113664952705968),
                Fp::new(5780497889736470261),
            ],
        ];

        for (input, expected) in input_data.iter().zip(output_data) {
            assert_eq!(expected, GriffinHash::hash(input).to_elements());
        }
    }
}
