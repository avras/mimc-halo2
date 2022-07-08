use criterion::{criterion_group, criterion_main, Criterion};
use mimc_halo2::mimc_feistel::{
    mimc_feistel_cipher::{
        MiMC5FeistelCipherConfig, MiMC5FeistelCipherPallasChip, MiMC5FeistelCipherChip, MiMC5FeistelCipherVestaChip
    },
    primitives::{mimc5_feistel_encrypt_pallas, mimc5_feistel_encrypt_vesta}
};
use rand::rngs::OsRng;
use pasta_curves::{pallas, vesta};

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::{Fp, Fq},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, SingleVerifier,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255}, arithmetic::Field,
};


#[derive(Debug, Clone)]
struct MiMC5FeistelCipherCircuitConfig {
    input : Column<Advice>,
    mimc_config: MiMC5FeistelCipherConfig,
}

#[derive(Default, Clone, Copy)]
struct MiMC5FeistelCipherPallasCircuit {
    pub message_left: Fp,
    pub message_right: Fp,
    pub key: Fp,
    pub ciphertext_left: Fp,
    pub ciphertext_right: Fp,
}

impl Circuit<Fp> for MiMC5FeistelCipherPallasCircuit {
    type Config = MiMC5FeistelCipherCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let circuit_input = meta.advice_column();
        meta.enable_equality(circuit_input);
        let state_left = meta.advice_column();
        let state_right = meta.advice_column();
        let key_column = meta.advice_column();
        let round_constants = meta.fixed_column();
        Self::Config {
            input: circuit_input,
            mimc_config: MiMC5FeistelCipherPallasChip::configure(meta, state_left, state_right, key_column, round_constants)
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = MiMC5FeistelCipherPallasChip::construct(config.mimc_config);

        let message_left = layouter.assign_region(
            || "load left part of message",
            |mut region| {
                region.assign_advice(
                    || "load input message",
                    config.input,
                    0,
                    || Value::known(self.message_left)
                )
            }  
        )?;

        let message_right = layouter.assign_region(
            || "load right part of message",
            |mut region| {
                region.assign_advice(
                    || "load input message",
                    config.input,
                    0,
                    || Value::known(self.message_right)
                )
            }  
        )?;

        let key = layouter.assign_region(
            || "load key",
            |mut region| {
                region.assign_advice(
                    || "load encryption key",
                    config.input,
                    0,
                    || Value::known(self.key)
                )
            }  
        )?;


        let (ciphertext_left, ciphertext_right) = chip.encrypt_message(
            layouter.namespace(|| "entire table"),
            &message_left,
            &message_right,
            &key,
        )?;

        layouter.assign_region(
            || "constrain output", 
            |mut region| {
                let expected_output_left = region.assign_advice(
                    || "load output", 
                    config.input,
                    0,
                    || Value::known(self.ciphertext_left),
                )?;
                let expected_output_right = region.assign_advice(
                    || "load output", 
                    config.input,
                    1,
                    || Value::known(self.ciphertext_right),
                )?;
                region.constrain_equal(ciphertext_left.cell(), expected_output_left.cell())?;
                region.constrain_equal(ciphertext_right.cell(), expected_output_right.cell())
            }
        )?;

        Ok(())
    }
}

#[derive(Default, Clone, Copy)]
struct MiMC5FeistelCipherVestaCircuit {
    pub message_left: Fq,
    pub message_right: Fq,
    pub key: Fq,
    pub ciphertext_left: Fq,
    pub ciphertext_right: Fq,
}

impl Circuit<Fq> for MiMC5FeistelCipherVestaCircuit {
    type Config = MiMC5FeistelCipherCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        let circuit_input = meta.advice_column();
        meta.enable_equality(circuit_input);
        let state_left = meta.advice_column();
        let state_right = meta.advice_column();
        let key_column = meta.advice_column();
        let round_constants = meta.fixed_column();
        Self::Config {
            input: circuit_input,
            mimc_config: MiMC5FeistelCipherVestaChip::configure(meta, state_left, state_right, key_column, round_constants)
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        let chip = MiMC5FeistelCipherVestaChip::construct(config.mimc_config);

        let message_left = layouter.assign_region(
            || "load left part of message",
            |mut region| {
                region.assign_advice(
                    || "load input message",
                    config.input,
                    0,
                    || Value::known(self.message_left)
                )
            }  
        )?;

        let message_right = layouter.assign_region(
            || "load right part of message",
            |mut region| {
                region.assign_advice(
                    || "load input message",
                    config.input,
                    0,
                    || Value::known(self.message_right)
                )
            }  
        )?;

        let key = layouter.assign_region(
            || "load key",
            |mut region| {
                region.assign_advice(
                    || "load encryption key",
                    config.input,
                    0,
                    || Value::known(self.key)
                )
            }  
        )?;


        let (ciphertext_left, ciphertext_right) = chip.encrypt_message(
            layouter.namespace(|| "entire table"),
            &message_left,
            &message_right,
            &key,
        )?;

        layouter.assign_region(
            || "constrain output", 
            |mut region| {
                let expected_output_left = region.assign_advice(
                    || "load output", 
                    config.input,
                    0,
                    || Value::known(self.ciphertext_left),
                )?;
                let expected_output_right = region.assign_advice(
                    || "load output", 
                    config.input,
                    1,
                    || Value::known(self.ciphertext_right),
                )?;
                region.constrain_equal(ciphertext_left.cell(), expected_output_left.cell())?;
                region.constrain_equal(ciphertext_right.cell(), expected_output_right.cell())
            }
        )?;

        Ok(())
    }
}


fn bench_mimc_feistel_pallas_cipher(c: &mut Criterion) {
    let log2_num_rows = 8;
    // Initialize the polynomial commitment parameters
    let params: Params<vesta::Affine> = Params::new(log2_num_rows);
  
    let empty_circuit = MiMC5FeistelCipherPallasCircuit::default();

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let mut rng = OsRng;
    let pallas_message_l = pallas::Base::random(rng);
    let pallas_message_r = pallas::Base::random(rng);
    let key = pallas::Base::random(rng);
    let mut state_l = pallas_message_l;
    let mut state_r = pallas_message_r;
    mimc5_feistel_encrypt_pallas(&mut state_l, &mut state_r, key);

    let circuit = MiMC5FeistelCipherPallasCircuit {
        message_left: pallas_message_l,
        message_right: pallas_message_r,
        key,
        ciphertext_left: state_l,
        ciphertext_right: state_r,
    };

    c.bench_function("mimc_feistel_cipher_pallas_prover", |b| {
        b.iter(|| {
            // Create a proof
            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
            create_proof(&params, &pk, &[circuit], &[&[]], &mut rng, &mut transcript)
                .expect("proof generation should not fail")
        })
    });

    // Create a proof
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit], &[&[]], &mut rng, &mut transcript)
        .expect("proof generation should not fail");
    let proof = transcript.finalize();

    c.bench_function("mimc_feistel_cipher_pallas_verifier", |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok());
        });
    });

}

fn bench_mimc_feistel_vesta_cipher(c: &mut Criterion) {
    let log2_num_rows = 8;
    // Initialize the polynomial commitment parameters
    let params: Params<pallas::Affine> = Params::new(log2_num_rows);
  
    let empty_circuit = MiMC5FeistelCipherVestaCircuit::default();

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let mut rng = OsRng;
    let vesta_message_l = vesta::Base::random(rng);
    let vesta_message_r = vesta::Base::random(rng);
    let key = vesta::Base::random(rng);
    let mut state_l = vesta_message_l;
    let mut state_r = vesta_message_r;
    mimc5_feistel_encrypt_vesta(&mut state_l, &mut state_r, key);

    let circuit = MiMC5FeistelCipherVestaCircuit {
        message_left: vesta_message_l,
        message_right: vesta_message_r,
        key,
        ciphertext_left: state_l,
        ciphertext_right: state_r,
    };

    c.bench_function("mimc_feistel_cipher_vesta_prover", |b| {
        b.iter(|| {
            // Create a proof
            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
            create_proof(&params, &pk, &[circuit], &[&[]], &mut rng, &mut transcript)
                .expect("proof generation should not fail")
        })
    });

    // Create a proof
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit], &[&[]], &mut rng, &mut transcript)
        .expect("proof generation should not fail");
    let proof = transcript.finalize();

    c.bench_function("mimc_feistel_cipher_vesta_verifier", |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok());
        });
    });

}

criterion_group!(benches, bench_mimc_feistel_pallas_cipher, bench_mimc_feistel_vesta_cipher);
criterion_main!(benches);