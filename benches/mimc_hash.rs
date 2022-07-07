use criterion::{criterion_group, criterion_main, Criterion};
use mimc_halo2::mimc::{
    mimc_hash::{
        MiMC5HashConfig, MiMC5HashPallasChip, MiMC5HashChip, MiMC5HashVestaChip
    },
    primitives::{mimc5_hash_pallas, mimc5_hash_vesta}
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
struct MiMC5HashCircuitConfig {
    input : Column<Advice>,
    mimc_config: MiMC5HashConfig,
}

#[derive(Default, Clone, Copy)]
struct MiMC5HashPallasCircuit {
    pub message: Fp,
    pub message_hash: Fp,
}

impl Circuit<Fp> for MiMC5HashPallasCircuit {
    type Config = MiMC5HashCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let circuit_input = meta.advice_column();
        meta.enable_equality(circuit_input);
        let state = meta.advice_column();
        let round_constants = meta.fixed_column();
        Self::Config {
            input: circuit_input,
            mimc_config: MiMC5HashPallasChip::configure(meta, state, round_constants)
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = MiMC5HashPallasChip::construct(config.mimc_config);

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

        let msg_hash = chip.hash_message(
            layouter.namespace(|| "entire table"),
            &message,
        )?;

        layouter.assign_region(
            || "constrain output", 
            |mut region| {
                let expected_output = region.assign_advice(
                    || "load output", 
                    config.input,
                    0,
                    || Value::known(self.message_hash),
                )?;
                region.constrain_equal(msg_hash.cell(), expected_output.cell())
            }
        )?;

        Ok(())
    }
}


#[derive(Default, Clone, Copy)]
struct MiMC5HashVestaCircuit {
    pub message: Fq,
    pub message_hash: Fq,
}

impl Circuit<Fq> for MiMC5HashVestaCircuit {
    type Config = MiMC5HashCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        let circuit_input = meta.advice_column();
        meta.enable_equality(circuit_input);
        let state = meta.advice_column();
        let round_constants = meta.fixed_column();
        Self::Config {
            input: circuit_input,
            mimc_config: MiMC5HashVestaChip::configure(meta, state, round_constants)
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        let chip = MiMC5HashVestaChip::construct(config.mimc_config);

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

        let msg_hash = chip.hash_message(
            layouter.namespace(|| "entire table"),
            &message,
        )?;

        layouter.assign_region(
            || "constrain output", 
            |mut region| {
                let expected_output = region.assign_advice(
                    || "load output", 
                    config.input,
                    0,
                    || Value::known(self.message_hash),
                )?;
                region.constrain_equal(msg_hash.cell(), expected_output.cell())
            }
        )?;

        Ok(())
    }

}

fn bench_mimc_pallas_hash(c: &mut Criterion) {
    let log2_num_rows = 7;
    // Initialize the polynomial commitment parameters
    let params: Params<vesta::Affine> = Params::new(log2_num_rows);
  
    let empty_circuit = MiMC5HashPallasCircuit::default();

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let mut rng = OsRng;
    let pallas_message = pallas::Base::random(rng);
    let mut state = pallas_message;
    mimc5_hash_pallas(&mut state);
    let pallas_message_hash = state;

    let circuit = MiMC5HashPallasCircuit {
        message: pallas_message,
        message_hash: pallas_message_hash
    };

    c.bench_function("mimc_hash_pallas_prover", |b| {
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

    c.bench_function("mimc_hash_pallas_verifier", |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok());
        });
    });

}

fn bench_mimc_vesta_hash(c: &mut Criterion) {
    let log2_num_rows = 7;
    // Initialize the polynomial commitment parameters
    let params: Params<pallas::Affine> = Params::new(log2_num_rows);
  
    let empty_circuit = MiMC5HashVestaCircuit::default();

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let mut rng = OsRng;
    let vesta_message = vesta::Base::random(rng);
    let mut state = vesta_message;
    mimc5_hash_vesta(&mut state);
    let vesta_message_hash = state;

    let circuit = MiMC5HashVestaCircuit {
        message: vesta_message,
        message_hash: vesta_message_hash
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

criterion_group!(benches, bench_mimc_pallas_hash, bench_mimc_vesta_hash);
criterion_main!(benches);