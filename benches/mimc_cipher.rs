use criterion::{criterion_group, criterion_main, Criterion};
use mimc_halo2::mimc::{
    mimc_cipher::{
        MiMC5CipherConfig, MiMC5CipherPallasChip, MiMC5CipherChip, MiMC5CipherVestaChip
    },
    primitives::{mimc5_encrypt_pallas, mimc5_encrypt_vesta}
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
struct MiMC5CipherCircuitConfig {
    input : Column<Advice>,
    mimc_config: MiMC5CipherConfig,
}

#[derive(Default, Clone, Copy)]
struct MiMC5CipherPallasCircuit {
    pub message: Fp,
    pub key: Fp,
    pub ciphertext: Fp,
}

impl Circuit<Fp> for MiMC5CipherPallasCircuit {
    type Config = MiMC5CipherCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let circuit_input = meta.advice_column();
        meta.enable_equality(circuit_input);
        let state = meta.advice_column();
        let key_column = meta.advice_column();
        let round_constants = meta.fixed_column();
        Self::Config {
            input: circuit_input,
            mimc_config: MiMC5CipherPallasChip::configure(meta, state, key_column, round_constants)
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = MiMC5CipherPallasChip::construct(config.mimc_config);

        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                region.assign_advice(
                    || "load input message",
                    config.input,
                    0,
                    || Value::known(self.message)
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

        let ciphertext = chip.encrypt_message(
            layouter.namespace(|| "entire table"),
            &message,
            &key,
        )?;

        layouter.assign_region(
            || "constrain output", 
            |mut region| {
                let expected_output = region.assign_advice(
                    || "load output", 
                    config.input,
                    0,
                    || Value::known(self.ciphertext),
                )?;
                region.constrain_equal(ciphertext.cell(), expected_output.cell())
            }
        )?;

        Ok(())
    }
}


#[derive(Default, Clone, Copy)]
struct MiMC5CipherVestaCircuit {
    pub message: Fq,
    pub key: Fq,
    pub ciphertext: Fq,
}

impl Circuit<Fq> for MiMC5CipherVestaCircuit {
    type Config = MiMC5CipherCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        let circuit_input = meta.advice_column();
        meta.enable_equality(circuit_input);
        let state = meta.advice_column();
        let key_column = meta.advice_column();
        let round_constants = meta.fixed_column();
        Self::Config {
            input: circuit_input,
            mimc_config: MiMC5CipherVestaChip::configure(meta, state, key_column, round_constants)
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        let chip = MiMC5CipherVestaChip::construct(config.mimc_config);

        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                region.assign_advice(
                    || "load input message",
                    config.input,
                    0,
                    || Value::known(self.message)
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

        let ciphertext = chip.encrypt_message(
            layouter.namespace(|| "entire table"),
            &message,
            &key,
        )?;

        layouter.assign_region(
            || "constrain output", 
            |mut region| {
                let expected_output = region.assign_advice(
                    || "load output", 
                    config.input,
                    0,
                    || Value::known(self.ciphertext),
                )?;
                region.constrain_equal(ciphertext.cell(), expected_output.cell())
            }
        )?;

        Ok(())
    }
}

fn bench_mimc_pallas_cipher(c: &mut Criterion) {
    let log2_num_rows = 7;
    // Initialize the polynomial commitment parameters
    let params: Params<vesta::Affine> = Params::new(log2_num_rows);
  
    let empty_circuit = MiMC5CipherPallasCircuit::default();

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let mut rng = OsRng;
    let pallas_message = pallas::Base::random(rng);
    let pallas_key = pallas::Base::random(rng);
    let mut state = pallas_message;
    mimc5_encrypt_pallas(&mut state, pallas_key);
    let pallas_ciphertext = state;

    let circuit = MiMC5CipherPallasCircuit {
        message: pallas_message,
        key: pallas_key,
        ciphertext: pallas_ciphertext
    };

    c.bench_function("mimc_cipher_pallas_prover", |b| {
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

    c.bench_function("mimc_cipher_pallas_verifier", |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok());
        });
    });

}

fn bench_mimc_vesta_cipher(c: &mut Criterion) {
    let log2_num_rows = 7;
    // Initialize the polynomial commitment parameters
    let params: Params<pallas::Affine> = Params::new(log2_num_rows);
  
    let empty_circuit = MiMC5CipherVestaCircuit::default();

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let mut rng = OsRng;
    let vesta_message = vesta::Base::random(rng);
    let vesta_key = vesta::Base::random(rng);
    let mut state = vesta_message;
    mimc5_encrypt_vesta(&mut state, vesta_key);
    let vesta_ciphertext = state;

    let circuit = MiMC5CipherVestaCircuit {
        message: vesta_message,
        key: vesta_key,
        ciphertext: vesta_ciphertext,
    };

    c.bench_function("mimc_hash_vesta_prover", |b| {
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

    c.bench_function("mimc_hash_vesta_verifier", |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok());
        });
    });

}

criterion_group!(benches, bench_mimc_pallas_cipher, bench_mimc_vesta_cipher);
criterion_main!(benches);