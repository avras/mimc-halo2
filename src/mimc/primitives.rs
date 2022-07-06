#[allow(unused_imports)]
use halo2_proofs::arithmetic::FieldExt;

#[cfg(test)]
pub(crate) fn mimc5_encrypt<F: FieldExt, const ROUNDS: usize>(
    state: &mut F,
    key: F,
    round_constants: [F; ROUNDS],
) {
    let pow_5 = |v: F| { v*v*v*v*v };

    for c in round_constants {
        *state = pow_5(*state + key + c);
    }
    *state = *state + key;
}

#[cfg(test)]
pub(crate) fn mimc5_hash<F: FieldExt, const ROUNDS: usize>(
    state: &mut F,
    round_constants: [F; ROUNDS],
) {
    mimc5_encrypt(state, F::zero(), round_constants);
}