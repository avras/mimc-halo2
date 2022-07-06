use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{
        Column, Advice, Fixed, Selector, ConstraintSystem, Expression, Error,
    },
    poly::Rotation,
    circuit::{
        Layouter, AssignedCell, Value,
    },
};
use pasta_curves::{Fp, Fq};

use super::round_constants::{MIMC_HASH_PALLAS_ROUND_CONSTANTS, MIMC_HASH_VESTA_ROUND_CONSTANTS};


#[allow(unused_variables, dead_code)]
#[derive(Debug, Clone)]
pub struct MiMC5CipherConfig {
    state: Column<Advice>,
    key_column: Column<Advice>,
    round_constants: Column<Fixed>,
    s_in_rounds: Selector,
    s_post_rounds: Selector,
}

pub trait MiMC5CipherChip<F: FieldExt> {
    fn construct(config: MiMC5CipherConfig) -> Self;

    fn get_round_constants() -> Vec<F>;

    fn get_config(&self) -> &MiMC5CipherConfig;

    fn configure(
        meta: &mut ConstraintSystem<F>,
        state: Column<Advice>,
        key_column: Column<Advice>,
        round_constants: Column<Fixed>,
    ) -> MiMC5CipherConfig {
        let s_in_rounds = meta.selector();
        let s_post_rounds = meta.selector();

        meta.enable_equality(state);
        meta.enable_equality(key_column);
        meta.enable_constant(round_constants);

        //  state                    | key_column   | round_constants   | selector
        //  x0 = message             |  key         |     c0            | 
        //  x1 = (x0+key+c0)^5       |  key         |     c1            | s_in_rounds
        //  x2 = (x1+key+c1)^5       |  key         |     c2            | s_in_rounds
        //  x3 = (x2+key+c2)^5       |  key         |     c3            | s_in_rounds
        //  x4 = (x3+key+c3)^5       |  key         |     c4            | s_in_rounds
        //       :                   |  :           |     :             |     :      
        //       :                   |  :           |     c109          |     :      
        //  x110 = (x109+key+c109)^5 |  key         |                   | s_in_rounds
        //  x110 + key               |              |                   | s_post_rounds

        meta.create_gate("MiMC5 encryption rounds", |meta| {
            let s = meta.query_selector(s_in_rounds);
            let pow_5_expr = |v: Expression<F>| {
                 v.clone() * v.clone() * v.clone() * v.clone() * v
            };
            let prev_state = meta.query_advice(state, Rotation::prev());
            let key = meta.query_advice(key_column, Rotation::cur());
            let prev_key = meta.query_advice(key_column, Rotation::cur());
            let rc = meta.query_fixed(round_constants, Rotation::prev());
            let current_state = meta.query_advice(state, Rotation::cur());
            vec![
                s.clone()*(current_state - pow_5_expr(prev_state + key.clone() + rc)),
                s*(prev_key-key)    // Ensure that the keys remain the same from one row to the next
            ]
        });

        meta.create_gate("post rounds key addition", |meta| {
            let s = meta.query_selector(s_post_rounds);
            let prev_state = meta.query_advice(state, Rotation::prev());
            let key = meta.query_advice(key_column, Rotation::prev()); // Using the key from the previous row
            let current_state = meta.query_advice(state, Rotation::cur());
            vec![s*(current_state - (prev_state + key))]
        });

        MiMC5CipherConfig {
            state,
            key_column,
            round_constants,
            s_in_rounds,
            s_post_rounds,
        }
    }

    fn encrypt_message(
        &self,
        mut layouter: impl Layouter<F>,
        message: F,
        key: F,
    ) -> Result<AssignedCell<F,F>, Error> {
        let config = self.get_config();

        let round_constant_values = Self::get_round_constants();

        layouter.assign_region(
            || "MiMC5 table",
            |mut region| {

                region.assign_advice(
                    || "message to be hashed",
                    config.state,
                    0,
                    || Value::known(message),
                )?;

                region.assign_advice(
                    || format!("key in row 0"),
                    config.key_column,
                    0,
                    || Value::known(key)
                )?;


                let pow_5 = |v: F| { v*v*v*v*v };

                let mut current_state = message;

                for i in 1..=round_constant_values.len() {
                    config.s_in_rounds.enable(&mut region, i)?;
                    region.assign_fixed(
                        || format!("round constant {:?}", i),
                        config.round_constants,
                        i-1,
                        || Value::known(round_constant_values[i-1]) // i starts at 1
                    )?;

                    region.assign_advice(
                        || format!("key in row {:?} ", i),
                        config.key_column,
                        i,
                        || Value::known(key)
                    )?;

                    current_state = pow_5(current_state + key + round_constant_values[i-1]);
                    region.assign_advice(
                        || format!("round {:?} output", i),
                        config.state,
                        i,
                        || Value::known(current_state)
                    )?;
                }

                current_state = current_state + key;

                let ciphertext =
                region.assign_advice(
                    || "final state",
                    config.state,
                    round_constant_values.len()+1,
                    || Value::known(current_state)
                )?;
                Ok(ciphertext)
            }
        )
    }
}

pub struct MiMC5CipherPallasChip {
    config: MiMC5CipherConfig
}

impl MiMC5CipherChip<Fp> for MiMC5CipherPallasChip {
    fn construct(config: MiMC5CipherConfig) -> Self {
        Self {
            config,
        }
    }

    fn get_config(&self) -> &MiMC5CipherConfig {
        &self.config
    }

    fn get_round_constants() -> Vec<Fp> {
        MIMC_HASH_PALLAS_ROUND_CONSTANTS.to_vec()
    }
}

pub struct MiMC5CipherVestaChip {
    config: MiMC5CipherConfig
}

impl MiMC5CipherChip<Fq> for MiMC5CipherVestaChip {
    fn construct(config: MiMC5CipherConfig) -> Self {
        Self {
            config,
        }
    }

    fn get_config(&self) -> &MiMC5CipherConfig {
        &self.config
    }

    fn get_round_constants() -> Vec<Fq> {
        MIMC_HASH_VESTA_ROUND_CONSTANTS.to_vec()
    }
}


#[cfg(test)]
mod tests {
    use crate::mimc::primitives::mimc5_encrypt;

    use super::*;
    use halo2_proofs::{dev::MockProver, pasta::Fp, plonk::Circuit, circuit::SimpleFloorPlanner};
    use crate::mimc::round_constants::{NUM_ROUNDS, MIMC_HASH_PALLAS_ROUND_CONSTANTS, MIMC_HASH_VESTA_ROUND_CONSTANTS};

    #[derive(Default)]
    struct MiMC5CipherPallasCircuit {
        pub message: Fp,
        pub key: Fp,
        pub ciphertext: Fp,
    }

    impl Circuit<Fp> for MiMC5CipherPallasCircuit {
        type Config = MiMC5CipherConfig;
        type FloorPlanner = SimpleFloorPlanner;
        
        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let state = meta.advice_column();
            let key_column = meta.advice_column();
            let round_constants = meta.fixed_column();
            MiMC5CipherPallasChip::configure(meta, state, key_column, round_constants)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = MiMC5CipherPallasChip::construct(config.clone());

            let ciphertext = chip.encrypt_message(
                layouter.namespace(|| "entire table"),
                self.message,
                self.key,
            )?;

            layouter.assign_region(
                || "constrain output", 
                |mut region| {
                    let expected_output = region.assign_advice(
                        || "load output", 
                        config.state,
                        0,
                        || Value::known(self.ciphertext),
                    )?;
                    region.constrain_equal(ciphertext.cell(), expected_output.cell())
                }
            )?;

            Ok(())
        }
    }

 
    #[test]
    fn test_mimc5_pallas_cipher() {
        let k = 7;

        let msg = Fp::from(0);
        let key = Fp::from(0);
        let mut output = msg;
        mimc5_encrypt::<Fp, { NUM_ROUNDS }>(&mut output, key, MIMC_HASH_PALLAS_ROUND_CONSTANTS);

        let circuit = MiMC5CipherPallasCircuit {
            message: msg,
            key,
            ciphertext: output,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

    }

    #[derive(Default)]
    struct MiMC5CipherVestaCircuit {
        pub message: Fq,
        pub key: Fq,
        pub ciphertext: Fq,
    }

    impl Circuit<Fq> for MiMC5CipherVestaCircuit {
        type Config = MiMC5CipherConfig;
        type FloorPlanner = SimpleFloorPlanner;
        
        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            let state = meta.advice_column();
            let round_constants = meta.fixed_column();
            let key_column = meta.advice_column();
            MiMC5CipherVestaChip::configure(meta, state, key_column, round_constants)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), Error> {
            let chip = MiMC5CipherVestaChip::construct(config.clone());

            let ciphertext = chip.encrypt_message(
                layouter.namespace(|| "entire table"),
                self.message,
                self.key,
            )?;

            layouter.assign_region(
                || "constrain output", 
                |mut region| {
                    let expected_output = region.assign_advice(
                        || "load output", 
                        config.state,
                        0,
                        || Value::known(self.ciphertext),
                    )?;
                    region.constrain_equal(ciphertext.cell(), expected_output.cell())
                }
            )?;

            Ok(())
        }
    }

     
    #[test]
    fn test_mimc5_vesta_cipher() {
        let k = 7;

        let msg = Fq::from(0);
        let key = Fq::from(0);
        let mut output = msg;
        mimc5_encrypt::<Fq, { NUM_ROUNDS }>(&mut output, key, MIMC_HASH_VESTA_ROUND_CONSTANTS);

        let circuit = MiMC5CipherVestaCircuit {
            message: msg,
            key,
            ciphertext: output,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

    }


    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_mimc5_pallas_cipher() {
        use plotters::prelude::*;
        let k = 7;
        let root = BitMapBackend::new("mimc5-pallas-cipher-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("MiMC Cipher Layout", ("sans-serif", 60)).unwrap();

        let circuit = MiMC5CipherPallasCircuit {
            message: Fp::zero(),
            key: Fp::zero(),
            ciphertext: Fp::zero(),
        };

        halo2_proofs::dev::CircuitLayout::default()
            .render(k, &circuit, &root)
            .unwrap();
    }
}