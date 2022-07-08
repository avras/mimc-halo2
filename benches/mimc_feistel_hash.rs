use criterion::{criterion_group, criterion_main, Criterion};
use mimc_halo2::mimc_feistel::{
    mimc_feistel_hash::{
        MiMC5FeistelHashConfig, MiMC5FeistelHashPallasChip, MiMC5FeistelHashChip, MiMC5FeistelHashVestaChip
    },
    primitives::{mimc5_feistel_hash_pallas, mimc5_feistel_hash_vesta}
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
struct MiMC5FeistelHashCircuitConfig {
    input : Column<Advice>,
    mimc_config: MiMC5FeistelHashConfig,
}

#[derive(Default, Clone, Copy)]
struct MiMC5FeistelHashPallasCircuit {
    pub message_left: Fp,
    pub message_right: Fp,
    pub message_hash_left: Fp,
    pub message_hash_right: Fp,
}

impl Circuit<Fp> for MiMC5FeistelHashPallasCircuit {
    type Config = MiMC5FeistelHashCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let circuit_input = meta.advice_column();
        meta.enable_equality(circuit_input);
        let state_left = meta.advice_column();
        let state_right = meta.advice_column();
        let round_constants = meta.fixed_column();
        Self::Config {
            input: circuit_input,
            mimc_config: MiMC5FeistelHashPallasChip::configure(meta, state_left, state_right, round_constants)
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = MiMC5FeistelHashPallasChip::construct(config.mimc_config);

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

        let (msg_hash_left, msg_hash_right) = chip.hash_message(
            layouter.namespace(|| "entire table"),
            &message_left,
            &message_right,
        )?;

        layouter.assign_region(
            || "constrain output", 
            |mut region| {
                let expected_output_left = region.assign_advice(
                    || "load output", 
                    config.input,
                    0,
                    || Value::known(self.message_hash_left),
                )?;
                let expected_output_right = region.assign_advice(
                    || "load output", 
                    config.input,
                    1,
                    || Value::known(self.message_hash_right),
                )?;
                region.constrain_equal(msg_hash_left.cell(), expected_output_left.cell())?;
                region.constrain_equal(msg_hash_right.cell(), expected_output_right.cell())
            }
        )?;

        Ok(())
    }
}


#[derive(Default, Clone, Copy)]
struct MiMC5FeistelHashVestaCircuit {
    pub message_left: Fq,
    pub message_right: Fq,
    pub message_hash_left: Fq,
    pub message_hash_right: Fq,
}

impl Circuit<Fq> for MiMC5FeistelHashVestaCircuit {
    type Config = MiMC5FeistelHashCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        let circuit_input = meta.advice_column();
        meta.enable_equality(circuit_input);
        let state_left = meta.advice_column();
        let state_right = meta.advice_column();
        let round_constants = meta.fixed_column();
        Self::Config {
            input: circuit_input,
            mimc_config: MiMC5FeistelHashVestaChip::configure(meta, state_left, state_right, round_constants)
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        let chip = MiMC5FeistelHashVestaChip::construct(config.mimc_config);

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

        let (msg_hash_left, msg_hash_right) = chip.hash_message(
            layouter.namespace(|| "entire table"),
            &message_left,
            &message_right,
        )?;

        layouter.assign_region(
            || "constrain output", 
            |mut region| {
                let expected_output_left = region.assign_advice(
                    || "load output", 
                    config.input,
                    0,
                    || Value::known(self.message_hash_left),
                )?;
                let expected_output_right = region.assign_advice(
                    || "load output", 
                    config.input,
                    1,
                    || Value::known(self.message_hash_right),
                )?;
                region.constrain_equal(msg_hash_left.cell(), expected_output_left.cell())?;
                region.constrain_equal(msg_hash_right.cell(), expected_output_right.cell())
            }
        )?;

        Ok(())
    }
}


fn bench_mimc_feistel_pallas_hash(c: &mut Criterion) {
    let log2_num_rows = 8;
    // Initialize the polynomial commitment parameters
    let params: Params<vesta::Affine> = Params::new(log2_num_rows);
  
    let empty_circuit = MiMC5FeistelHashPallasCircuit::default();

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let mut rng = OsRng;
    let pallas_message_l = pallas::Base::random(rng);
    let pallas_message_r = pallas::Base::random(rng);
    let mut state_l = pallas_message_l;
    let mut state_r = pallas_message_r;
    mimc5_feistel_hash_pallas(&mut state_l, &mut state_r);

    let circuit = MiMC5FeistelHashPallasCircuit {
        message_left: pallas_message_l,
        message_right: pallas_message_r,
        message_hash_left: state_l,
        message_hash_right: state_r,
    };

    c.bench_function("mimc_feistel_hash_pallas_prover", |b| {
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

    c.bench_function("mimc_feistel_hash_pallas_verifier", |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok());
        });
    });

}

fn bench_mimc_feistel_vesta_hash(c: &mut Criterion) {
    let log2_num_rows = 8;
    // Initialize the polynomial commitment parameters
    let params: Params<pallas::Affine> = Params::new(log2_num_rows);
  
    let empty_circuit = MiMC5FeistelHashVestaCircuit::default();

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let mut rng = OsRng;
    let vesta_message_l = vesta::Base::random(rng);
    let vesta_message_r = vesta::Base::random(rng);
    let mut state_l = vesta_message_l;
    let mut state_r = vesta_message_r;
    mimc5_feistel_hash_vesta(&mut state_l, &mut state_r);

    let circuit = MiMC5FeistelHashVestaCircuit {
        message_left: vesta_message_l,
        message_right: vesta_message_r,
        message_hash_left: state_l,
        message_hash_right: state_r,
    };

    c.bench_function("mimc_feistel_hash_vesta_prover", |b| {
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

    c.bench_function("mimc_feistel_hash_vesta_verifier", |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok());
        });
    });

}

criterion_group!(benches, bench_mimc_feistel_pallas_hash, bench_mimc_feistel_vesta_hash);
criterion_main!(benches);