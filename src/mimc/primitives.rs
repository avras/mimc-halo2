use halo2_proofs::arithmetic::FieldExt;
use pasta_curves::{Fp, Fq};
use crate::mimc::round_constants::NUM_ROUNDS;
use crate::mimc::round_constants::{MIMC_PALLAS_ROUND_CONSTANTS, MIMC_VESTA_ROUND_CONSTANTS};

pub fn mimc5_encrypt<F: FieldExt, const ROUNDS: usize>(
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

pub fn mimc5_hash<F: FieldExt, const ROUNDS: usize>(
    state: &mut F,
    round_constants: [F; ROUNDS],
) {
    mimc5_encrypt(state, F::zero(), round_constants);
}

pub fn mimc5_hash_pallas(
    state: &mut Fp,
) {
    mimc5_hash::<Fp, NUM_ROUNDS>(state, MIMC_PALLAS_ROUND_CONSTANTS);
}

pub fn mimc5_hash_vesta(
    state: &mut Fq,
) {
    mimc5_hash::<Fq, NUM_ROUNDS>(state, MIMC_VESTA_ROUND_CONSTANTS);
}

pub fn mimc5_encrypt_pallas(
    state: &mut Fp,
    key: Fp,
) {
    mimc5_encrypt::<Fp, NUM_ROUNDS>(state, key, MIMC_PALLAS_ROUND_CONSTANTS);
}

pub fn mimc5_encrypt_vesta(
    state: &mut Fq,
    key: Fq,
) {
    mimc5_encrypt::<Fq, NUM_ROUNDS>(state, key, MIMC_VESTA_ROUND_CONSTANTS);
}