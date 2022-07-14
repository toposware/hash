use cheetah::Fp;

#[inline(always)]
/// Squares each element of `base` M times, then performs
/// a product term by term with `tail`.
pub(crate) fn square_assign_multi_and_multiply<const N: usize, const M: usize>(
    base: [Fp; N],
    tail: [Fp; N],
) -> [Fp; N] {
    let mut result = base;
    for _ in 0..M {
        result.iter_mut().for_each(|r| *r = r.square());
    }

    result.iter_mut().zip(&tail).for_each(|(r, t)| *r *= t);
    result
}

#[inline(always)]
/// Applies exponentiation of the current hash
/// state elements with the Rescue S-Box.
pub(crate) fn apply_rescue_sbox<const STATE_WIDTH: usize>(state: &mut [Fp; STATE_WIDTH]) {
    state.iter_mut().for_each(|v| {
        let t2 = v.square();
        let t4 = t2.square();
        *v *= t2 * t4;
    });
}

#[inline(always)]
/// Applies exponentiation of the current hash state
/// elements with the Rescue inverse S-Box.
pub(crate) fn apply_rescue_inv_sbox<const STATE_WIDTH: usize>(state: &mut [Fp; STATE_WIDTH]) {
    let mut t1 = *state;
    t1.iter_mut().for_each(|t| *t = t.square());

    let mut t2 = t1;
    t2.iter_mut().for_each(|t| *t = t.square());

    let t3 = square_assign_multi_and_multiply::<STATE_WIDTH, 3>(t2, t2);
    let t4 = square_assign_multi_and_multiply::<STATE_WIDTH, 6>(t3, t3);
    let t4 = square_assign_multi_and_multiply::<STATE_WIDTH, 12>(t4, t4);
    let t5 = square_assign_multi_and_multiply::<STATE_WIDTH, 6>(t4, t3);
    let t6 = square_assign_multi_and_multiply::<STATE_WIDTH, 31>(t5, t5);

    for (i, s) in state.iter_mut().enumerate() {
        let a = (t6[i].square() * t5[i]).square().square();
        let b = t1[i] * t2[i] * *s;
        *s = a * b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Base power map of the Rescue-Prime S-Box
    const ALPHA: u64 = 7;

    /// Inverse power map of the Rescue-Prime S-Box
    const INV_ALPHA: u64 = 10540996611094048183;

    #[test]
    fn test_square_assign_multi_and_multiply() {
        let mut state = [Fp::zero(); 10];
        let zeros = [Fp::zero(); 10];
        let ones = [Fp::one(); 10];
        let mut rng = OsRng;

        for _ in 0..10 {
            for s in state.iter_mut() {
                *s = Fp::random(&mut rng);
            }

            assert_eq!(
                square_assign_multi_and_multiply::<10, 0>(state, zeros),
                zeros
            );
            assert_eq!(
                square_assign_multi_and_multiply::<10, 0>(zeros, state),
                zeros
            );
            assert_eq!(square_assign_multi_and_multiply::<10, 0>(ones, ones), ones);
            assert_eq!(
                square_assign_multi_and_multiply::<10, 0>(state, ones),
                state
            );

            assert_eq!(
                square_assign_multi_and_multiply::<10, 1>(state, zeros),
                zeros
            );
            assert_eq!(
                square_assign_multi_and_multiply::<10, 1>(zeros, state),
                zeros
            );
            assert_eq!(square_assign_multi_and_multiply::<10, 1>(ones, ones), ones);
        }
    }

    #[test]
    fn test_rescue_sbox() {
        let mut state = [Fp::zero(); 12];
        let mut rng = OsRng;

        for _ in 0..100 {
            for s in state.iter_mut() {
                *s = Fp::random(&mut rng);
            }

            // Check Forward S-Box

            let mut state_2 = state;
            state_2.iter_mut().for_each(|v| {
                *v = v.exp(ALPHA);
            });

            apply_rescue_sbox(&mut state);

            assert_eq!(state, state_2);

            // Check Backward S-Box

            let mut state_2 = state;
            state_2.iter_mut().for_each(|v| {
                *v = v.exp(INV_ALPHA);
            });

            apply_rescue_inv_sbox(&mut state);

            assert_eq!(state, state_2);
        }
    }
}
