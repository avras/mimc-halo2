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

use super::round_constants::{MIMC_FEISTEL_PALLAS_ROUND_CONSTANTS, MIMC_FEISTEL_VESTA_ROUND_CONSTANTS};


#[allow(unused_variables, dead_code)]
#[derive(Debug, Clone)]
pub struct MiMC5FeistelCipherConfig {
    state_left: Column<Advice>,
    state_right: Column<Advice>,
    key_column: Column<Advice>,
    round_constants: Column<Fixed>,
    s_inner_rounds: Selector,
    s_last_round: Selector,
}

pub trait MiMC5FeistelCipherChip<F: FieldExt> {
    fn construct(config: MiMC5FeistelCipherConfig) -> Self;

    fn get_round_constants() -> Vec<F>;

    fn get_config(&self) -> &MiMC5FeistelCipherConfig;

    fn configure(
        meta: &mut ConstraintSystem<F>,
        state_left: Column<Advice>,
        state_right: Column<Advice>,
        key_column: Column<Advice>,
        round_constants: Column<Fixed>,
    ) -> MiMC5FeistelCipherConfig {
        let s_inner_rounds = meta.selector();
        let s_last_round = meta.selector();

        meta.enable_equality(state_left);
        meta.enable_equality(state_right);
        meta.enable_equality(key_column);
        meta.enable_constant(round_constants);

        //  state_left                           | state_right                      | key_column | round_constants   | selector
        //  xL,0 = xL                            | xR,0 = xR                        | k          |     c0            | 
        //  xL,1 = xR,0 + (xL,0 + k + c0)^5      | xR,1 = xL,0                      | k          |     c1            | s_inner_rounds
        //  xL,2 = xR,1 + (xL,1 + k + c1)^5      | xR,2 = xL,1                      | k          |     c2            | s_inner_rounds
        //  xL,3 = xR,2 + (xL,2 + k + c2)^5      | xR,3 = xL,2                      | k          |     c3            | s_inner_rounds
        //       :                               |                                  | :          |     :             |     :      
        //  xL,219 = xR,218 + (xL,2 + k + c2)^5  | xR,219 = xL,218                  | k          |     c219 = 0      | s_inner_rounds
        //  xL,220 = xL,219                      | xR,220 = xR,219 + (xL,219 + k)^5 | k          |                   | s_last_round

        let pow_5_expr = |v: Expression<F>| {
                v.clone() * v.clone() * v.clone() * v.clone() * v
        };

        meta.create_gate("MiMC5 Feistel encryption inner rounds", |meta| {
            let s = meta.query_selector(s_inner_rounds);
            let prev_state_left = meta.query_advice(state_left, Rotation::prev());
            let prev_state_right = meta.query_advice(state_right, Rotation::prev());

            let rc = meta.query_fixed(round_constants, Rotation::prev());
            let key = meta.query_advice(key_column, Rotation::cur());
            let prev_key = meta.query_advice(key_column, Rotation::cur());
            
            let current_state_left = meta.query_advice(state_left, Rotation::cur());
            let current_state_right = meta.query_advice(state_right, Rotation::cur());
            vec![
                s.clone()*(current_state_left - prev_state_right - pow_5_expr(prev_state_left.clone() + key.clone() + rc)),
                s.clone()*(current_state_right - prev_state_left),
                s*(prev_key-key)    // Ensure that the keys remain the same from one row to the next
            ]
        });

        meta.create_gate("MiMC5 Feistel last round", |meta| {
            let s = meta.query_selector(s_last_round);
            let prev_state_left = meta.query_advice(state_left, Rotation::prev());
            let prev_state_right = meta.query_advice(state_right, Rotation::prev());

            let key = meta.query_advice(key_column, Rotation::cur());
            let prev_key = meta.query_advice(key_column, Rotation::cur());

            let current_state_left = meta.query_advice(state_left, Rotation::cur());
            let current_state_right = meta.query_advice(state_right, Rotation::cur());
            vec![
                s.clone()*(current_state_left - prev_state_left.clone()),
                s.clone()*(current_state_right - prev_state_right - pow_5_expr(prev_state_left + key.clone())),
                s*(prev_key-key)    // Ensure that the keys remain the same from one row to the next
            ]
        });

        MiMC5FeistelCipherConfig {
            state_left,
            state_right,
            key_column,
            round_constants,
            s_inner_rounds,
            s_last_round,
        }
    }

    fn encrypt_message(
        &self,
        mut layouter: impl Layouter<F>,
        message_left: &AssignedCell<F, F>,
        message_right: &AssignedCell<F, F>,
        key: &AssignedCell<F, F>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F,F>), Error> {
        let config = self.get_config();

        let round_constant_values = Self::get_round_constants();
        layouter.assign_region(
            || "MiMC5 Feistel table",
            |mut region| {

                region.assign_advice(
                    || "left part of message to be hashed",
                    config.state_left,
                    0,
                    || message_left.value().copied(),
                )?;

                region.assign_advice(
                    || "right part of message to be hashed",
                    config.state_right,
                    0,
                    || message_right.value().copied(),
                )?;

                region.assign_advice(
                    || format!("key in row 0"),
                    config.key_column,
                    0,
                    || key.value().copied(),
                )?;

                let pow_5 = |v: Value<F>| { v*v*v*v*v };

                let mut current_state_left = message_left.value().copied();
                let mut current_state_right = message_right.value().copied();

                let state_cell_left;
                let state_cell_right;

                for i in 1..round_constant_values.len() { // i goes from 1 to 219
                    config.s_inner_rounds.enable(&mut region, i)?;
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
                        || key.value().copied()
                    )?;


                    let temp = current_state_right + pow_5(current_state_left + key.value().copied() + Value::known(round_constant_values[i-1]));
                    current_state_right = current_state_left;
                    current_state_left = temp;
                    
                    region.assign_advice(
                        || format!("round {:?} output on the left", i),
                        config.state_left,
                        i,
                        || current_state_left
                    )?;

                    region.assign_advice(
                        || format!("round {:?} output on the right", i),
                        config.state_right,
                        i,
                        || current_state_right
                    )?;
                }

                config.s_last_round.enable(&mut region, round_constant_values.len())?;
                region.assign_advice(
                    || format!("key in row {:?}", round_constant_values.len()),
                    config.key_column,
                    round_constant_values.len(),
                    || key.value().copied(),
                )?;

                current_state_right = current_state_right + pow_5(current_state_left + key.value().copied());
                state_cell_left =
                region.assign_advice(
                    || "last round output on the left",
                    config.state_left,
                    round_constant_values.len(),
                    || current_state_left
                )?;
                state_cell_right =
                region.assign_advice(
                    || "last round output on the right",
                    config.state_right,
                    round_constant_values.len(),
                    || current_state_right
                )?;

                // The left output is unchanged in the last round

                Ok((state_cell_left, state_cell_right))
            }
        )
    }
}

pub struct MiMC5FeistelCipherPallasChip {
    config: MiMC5FeistelCipherConfig
}

impl MiMC5FeistelCipherChip<Fp> for MiMC5FeistelCipherPallasChip {
    fn construct(config: MiMC5FeistelCipherConfig) -> Self {
        Self {
            config,
        }
    }

    fn get_config(&self) -> &MiMC5FeistelCipherConfig {
        &self.config
    }

    fn get_round_constants() -> Vec<Fp> {
        MIMC_FEISTEL_PALLAS_ROUND_CONSTANTS.to_vec()
    }
}

pub struct MiMC5FeistelCipherVestaChip {
    config: MiMC5FeistelCipherConfig
}

impl MiMC5FeistelCipherChip<Fq> for MiMC5FeistelCipherVestaChip {
    fn construct(config: MiMC5FeistelCipherConfig) -> Self {
        Self {
            config,
        }
    }

    fn get_config(&self) -> &MiMC5FeistelCipherConfig {
        &self.config
    }

    fn get_round_constants() -> Vec<Fq> {
        MIMC_FEISTEL_VESTA_ROUND_CONSTANTS.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::mimc_feistel::primitives::{mimc5_feistel_encrypt_pallas, mimc5_feistel_encrypt_vesta};

    use super::*;
    use halo2_proofs::{dev::MockProver, pasta::Fp, plonk::Circuit, circuit::SimpleFloorPlanner};

    #[derive(Debug, Clone)]
    struct MiMC5FeistelCipherCircuitConfig {
        input : Column<Advice>,
        mimc_config: MiMC5FeistelCipherConfig,
    }

    #[derive(Default)]
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

 
    #[test]
    fn test_mimc5_feistel_pallas_cipher() {
        let k = 8;

        let msg_l = Fp::from(1);
        let msg_r = Fp::from(2);
        let key = Fp::from(3);
        let mut output_l = msg_l;
        let mut output_r = msg_r;
        mimc5_feistel_encrypt_pallas(&mut output_l, &mut output_r, key);

        let circuit = MiMC5FeistelCipherPallasCircuit {
            message_left: msg_l,
            message_right: msg_r,
            key,
            ciphertext_left: output_l,
            ciphertext_right: output_r,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

    }

    #[derive(Default)]
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

 
    #[test]
    fn test_mimc5_feistel_vesta_cipher() {
        let k = 8;

        let msg_l = Fq::from(1);
        let msg_r = Fq::from(2);
        let key = Fq::from(3);
        let mut output_l = msg_l;
        let mut output_r = msg_r;
        mimc5_feistel_encrypt_vesta(&mut output_l, &mut output_r, key);

        let circuit = MiMC5FeistelCipherVestaCircuit {
            message_left: msg_l,
            message_right: msg_r,
            key,
            ciphertext_left: output_l,
            ciphertext_right: output_r,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

    }



    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_mimc5_feistel_pallas_cipher() {
        use plotters::prelude::*;
        let k = 8;
        let root = BitMapBackend::new("mimc5-feistel-pallas-cipher-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("MiMC Feistel Cipher Layout", ("sans-serif", 60)).unwrap();

        let circuit = MiMC5FeistelCipherPallasCircuit {
            message_left: Fp::zero(),
            message_right: Fp::zero(),
            key: Fp::zero(),
            ciphertext_left: Fp::zero(),
            ciphertext_right: Fp::zero(),
        };

        halo2_proofs::dev::CircuitLayout::default()
            .render(k, &circuit, &root)
            .unwrap();
    }
}