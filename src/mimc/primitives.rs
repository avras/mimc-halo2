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

#[cfg(test)]
mod tests {
    use super::{mimc5_hash_pallas, mimc5_hash_vesta, mimc5_encrypt_pallas, mimc5_encrypt_vesta};
    use pasta_curves::{pallas, vesta};

    #[test]
    fn test_mimc5_hash_primitives () {
        let pallas_message = pallas::Base::from(1);
        // Reference output calculated using code at
        // https://github.com/avras/pasta-mimc/blob/main/code/mimc_x5_pallas.sage
        // Run "sage mimc5_pallas.sage 1"
        let pallas_expected_hash = pallas::Base::from_raw([
            0xf1b6_b542_248d_7935,
            0x03eb_dcc8_c1c9_92ae,
            0x8394_9bc2_0824_559a,
            0x0dbf_6bb3_67a6_b1aa,
        ]);
        let mut pallas_output = pallas_message;
        mimc5_hash_pallas(&mut pallas_output);
        assert_eq!(pallas_expected_hash, pallas_output);

        let vesta_message = vesta::Base::from(1);
        // Reference output calculated using code at
        // https://github.com/avras/pasta-mimc/blob/main/code/mimc_x5_vesta.sage
        // Run "sage mimc5_vesta.sage 1"
        let vesta_expected_hash = vesta::Base::from_raw([
            0x2f62_41c4_30c0_0c1e,
            0xdc2a_13c6_2853_b644,
            0x96e1_b2e4_7bd8_6951,
            0x3465_eae0_fdd1_272c,
        ]);
        let mut vesta_output = vesta_message;
        mimc5_hash_vesta(&mut vesta_output);
        assert_eq!(vesta_expected_hash, vesta_output);
    }

    #[test]
    fn test_mimc5_cipher_primitives () {
        let pallas_message = pallas::Base::from(1);
        let pallas_key = pallas::Base::from(2);
        // Reference output calculated using code at
        // https://github.com/avras/pasta-mimc/blob/main/code/mimc_x5_pallas.sage
        // Run "sage mimc5_pallas.sage 1 2"
        let pallas_expected_ciphertext = pallas::Base::from_raw([
            0x8bf6_93ca_ffae_5056,
            0xf0c3_5ee3_97a5_7b7c,
            0x16f8_c2f1_23c2_eb57,
            0x13a1_3ee3_8180_ed5c,
        ]);
        let mut pallas_output = pallas_message;
        mimc5_encrypt_pallas(&mut pallas_output, pallas_key);
        assert_eq!(pallas_expected_ciphertext, pallas_output);

        let vesta_message = vesta::Base::from(1);
        let vesta_key = vesta::Base::from(2);
        // Reference output calculated using code at
        // https://github.com/avras/pasta-mimc/blob/main/code/mimc_x5_vesta.sage
        // Run "sage mimc5_vesta.sage 1 2"
        let vesta_expected_ciphertext = vesta::Base::from_raw([
            0xd0e9_a4b0_8586_fdf1,
            0x51e6_82df_2b86_3e68,
            0x54b1_7a7a_4b55_2509,
            0x2cc4_2ee2_f700_bd43,
        ]);
        let mut vesta_output = vesta_message;
        mimc5_encrypt_vesta(&mut vesta_output, vesta_key);
        assert_eq!(vesta_expected_ciphertext, vesta_output);

    }
}