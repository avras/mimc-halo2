use halo2_proofs::arithmetic::FieldExt;
use pasta_curves::{Fp, Fq};
use crate::mimc_feistel::round_constants::NUM_ROUNDS;
use crate::mimc_feistel::round_constants::{MIMC_FEISTEL_PALLAS_ROUND_CONSTANTS, MIMC_FEISTEL_VESTA_ROUND_CONSTANTS};

pub fn mimc5_feistel_encrypt<F: FieldExt, const ROUNDS: usize>(
    state_l: &mut F,
    state_r: &mut F,
    key: F,
    round_constants: [F; ROUNDS],
) {
    let pow_5 = |v: F| { v*v*v*v*v };

    for i in 0..ROUNDS-1 {
        let new_state_l = *state_r + pow_5(*state_l + key + round_constants[i]);
        let new_state_r = *state_l;
        *state_l = new_state_l;
        *state_r = new_state_r;
    }
    *state_r = *state_r + pow_5(*state_l + key);
}

pub fn mimc5_feistel_hash<F: FieldExt, const ROUNDS: usize>(
    state_l: &mut F,
    state_r: &mut F,
    round_constants: [F; ROUNDS],
) {
    mimc5_feistel_encrypt(state_l, state_r, F::zero(), round_constants);
}

pub fn mimc5_feistel_hash_pallas(
    state_l: &mut Fp,
    state_r: &mut Fp,
) {
    mimc5_feistel_hash::<Fp, NUM_ROUNDS>(state_l, state_r, MIMC_FEISTEL_PALLAS_ROUND_CONSTANTS);
}

pub fn mimc5_feistel_hash_vesta(
    state_l: &mut Fq,
    state_r: &mut Fq,
) {
    mimc5_feistel_hash::<Fq, NUM_ROUNDS>(state_l, state_r, MIMC_FEISTEL_VESTA_ROUND_CONSTANTS);
}

pub fn mimc5_feistel_encrypt_pallas(
    state_l: &mut Fp,
    state_r: &mut Fp,
    key: Fp,
) {
    mimc5_feistel_encrypt::<Fp, NUM_ROUNDS>(state_l, state_r, key, MIMC_FEISTEL_PALLAS_ROUND_CONSTANTS);
}

pub fn mimc5_feistel_encrypt_vesta(
    state_l: &mut Fq,
    state_r: &mut Fq,
    key: Fq,
) {
    mimc5_feistel_encrypt::<Fq, NUM_ROUNDS>(state_l, state_r, key, MIMC_FEISTEL_VESTA_ROUND_CONSTANTS);
}

#[cfg(test)]
mod tests {
    use super::{
        mimc5_feistel_hash_pallas, mimc5_feistel_hash_vesta,
        mimc5_feistel_encrypt_pallas, mimc5_feistel_encrypt_vesta
    };
    use pasta_curves::{pallas, vesta};

    #[test]
    fn test_mimc5_feistel_hash_primitives () {
        let pallas_message_l = pallas::Base::from(1);
        let pallas_message_r = pallas::Base::from(2);
        // Reference output calculated using code at
        // https://github.com/avras/pasta-mimc/blob/main/code/mimc_feistel_x5_pallas.sage
        // Run "sage mimc5_feistel_x5_pallas.sage 1 2"
        let pallas_expected_hash_l = pallas::Base::from_raw([
            0x22d1_0a2d_8515_cc2d,
            0xc495_18f7_1470_0b8d,
            0x502e_f77c_51dc_8172,
            0x3dcf_0833_bf9a_d066,
        ]);
        
        let pallas_expected_hash_r = pallas::Base::from_raw([
            0x72da_1f96_71a3_f1b1,
            0xd5dd_1d42_ebff_40f0,
            0x7922_bc44_bb42_d4e9,
            0x0911_f7db_0997_f9d7,
        ]);
        let mut pallas_output_l = pallas_message_l;
        let mut pallas_output_r = pallas_message_r;
        mimc5_feistel_hash_pallas(&mut pallas_output_l, &mut pallas_output_r);

        assert_eq!(pallas_expected_hash_l, pallas_output_l, "Checking equality of left outputs");
        assert_eq!(pallas_expected_hash_r, pallas_output_r, "Checking equality of right outputs");

        let vesta_message_l = vesta::Base::from(1);
        let vesta_message_r = vesta::Base::from(2);
        // Reference output calculated using code at
        // https://github.com/avras/pasta-mimc/blob/main/code/mimc_feistel_x5_vesta.sage
        // Run "sage mimc5_feistel_x5_vesta.sage 1 2"
        let vesta_expected_hash_l = vesta::Base::from_raw([
            0x218b_c18e_d0d8_9468,
            0x165a_de14_8b6d_1abe,
            0x1082_4fa4_0eea_3d54,
            0x31e1_826e_8ba5_ceea,
        ]);
        
        let vesta_expected_hash_r = vesta::Base::from_raw([
            0x5a81_8c06_83c4_7b91,
            0x9148_fc97_2d63_2962,
            0x27cf_83ae_d4c0_1228,
            0x0f62_1ce4_da3d_9c64,
        ]);

        let mut vesta_output_l = vesta_message_l;
        let mut vesta_output_r = vesta_message_r;
        mimc5_feistel_hash_vesta(&mut vesta_output_l, &mut vesta_output_r);

        assert_eq!(vesta_expected_hash_l, vesta_output_l, "Checking equality of left outputs");
        assert_eq!(vesta_expected_hash_r, vesta_output_r, "Checking equality of right outputs");

    }

    #[test]
    fn test_mimc5_feistel_cipher_primitives () {
        let pallas_message_l = pallas::Base::from(1);
        let pallas_message_r = pallas::Base::from(2);
        let pallas_key = pallas::Base::from(3);
        // Reference output calculated using code at
        // https://github.com/avras/pasta-mimc/blob/main/code/mimc_feistel_x5_pallas.sage
        // Run "sage mimc5_feistel_x5_pallas.sage 1 2 3"
        let pallas_expected_ciphertext_l = pallas::Base::from_raw([
            0x7092_dffa_d96e_c69a,
            0xa181_bef7_7cdb_64f3,
            0x047d_752b_f603_93a7,
            0x10c2_b3e1_1d36_a3ed,
        ]);
        
        let pallas_expected_ciphertext_r = pallas::Base::from_raw([
            0x1bbb_1d8c_5f52_a4da,
            0x6912_6540_9021_b693,
            0x1529_9395_51cf_4d8d,
            0x0e79_a2cc_62eb_9474,
        ]);
        
        let mut pallas_output_l = pallas_message_l;
        let mut pallas_output_r = pallas_message_r;
        mimc5_feistel_encrypt_pallas(&mut pallas_output_l, &mut pallas_output_r, pallas_key);

        assert_eq!(pallas_expected_ciphertext_l, pallas_output_l, "Checking equality of left outputs");
        assert_eq!(pallas_expected_ciphertext_r, pallas_output_r, "Checking equality of right outputs");

        let vesta_message_l = vesta::Base::from(1);
        let vesta_message_r = vesta::Base::from(2);
        let vesta_key = vesta::Base::from(3);
        // Reference output calculated using code at
        // https://github.com/avras/pasta-mimc/blob/main/code/mimc_feistel_x5_vesta.sage
        // Run "sage mimc5_feistel_x5_vesta.sage 1 2 3"
        let vesta_expected_ciphertext_l = vesta::Base::from_raw([
            0x95f9_6897_d7e9_aba1,
            0x7b0c_f5ea_8886_16b2,
            0xfed7_07cd_2e6b_f8ca,
            0x0258_6239_4281_ca3b,
        ]);
        
        let vesta_expected_ciphertext_r = vesta::Base::from_raw([
            0x27bb_f0cc_5fca_1117,
            0xe209_de81_fa45_b479,
            0xeda6_d152_c447_c15c,
            0x1ac1_e44f_18d5_bfd9,
        ]);

        let mut vesta_output_l = vesta_message_l;
        let mut vesta_output_r = vesta_message_r;
        mimc5_feistel_encrypt_vesta(&mut vesta_output_l, &mut vesta_output_r, vesta_key);

        assert_eq!(vesta_expected_ciphertext_l, vesta_output_l, "Checking equality of left outputs");
        assert_eq!(vesta_expected_ciphertext_r, vesta_output_r, "Checking equality of right outputs");
    }
}