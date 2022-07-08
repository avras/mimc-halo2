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
pub struct MiMC5FeistelHashConfig {
    state_left: Column<Advice>,
    state_right: Column<Advice>,
    round_constants: Column<Fixed>,
    s_inner_rounds: Selector,
    s_last_round: Selector,
}

pub trait MiMC5FeistelHashChip<F: FieldExt> {
    fn construct(config: MiMC5FeistelHashConfig) -> Self;

    fn get_round_constants() -> Vec<F>;

    fn get_config(&self) -> &MiMC5FeistelHashConfig;

    fn configure(
        meta: &mut ConstraintSystem<F>,
        state_left: Column<Advice>,
        state_right: Column<Advice>,
        round_constants: Column<Fixed>,
    ) -> MiMC5FeistelHashConfig {
        let s_inner_rounds = meta.selector();
        let s_last_round = meta.selector();

        meta.enable_equality(state_left);
        meta.enable_equality(state_right);
        meta.enable_constant(round_constants);

        //  state_left                     | state_right                  | round_constants   | selector
        //  xL,0 = xL                      | xR,0 = xR                    |     c0            | 
        //  xL,1 = xR,0 + (xL,0+c0)^5      | xR,1 = xL,0                  |     c1            | s_inner_rounds
        //  xL,2 = xR,1 + (xL,1+c1)^5      | xR,2 = xL,1                  |     c2            | s_inner_rounds
        //  xL,3 = xR,2 + (xL,2+c2)^5      | xR,3 = xL,2                  |     c3            | s_inner_rounds
        //       :                         |                              |     :             |     :      
        //  xL,219 = xR,218 + (xL,2+c2)^5  | xR,219 = xL,218              |     c219 = 0      | s_inner_rounds
        //  xL,220 = xL,219                | xR,220 = xR,219 + (xL,219)^5 |                   | s_last_round

        let pow_5_expr = |v: Expression<F>| {
                v.clone() * v.clone() * v.clone() * v.clone() * v
        };

        meta.create_gate("MiMC5 Feistel inner rounds", |meta| {
            let s = meta.query_selector(s_inner_rounds);
            let prev_state_left = meta.query_advice(state_left, Rotation::prev());
            let prev_state_right = meta.query_advice(state_right, Rotation::prev());
            let rc = meta.query_fixed(round_constants, Rotation::prev());
            let current_state_left = meta.query_advice(state_left, Rotation::cur());
            let current_state_right = meta.query_advice(state_right, Rotation::cur());
            vec![
                s.clone()*(current_state_left - prev_state_right - pow_5_expr(prev_state_left.clone() +  rc)),
                s.clone()*(current_state_right - prev_state_left)
            ]
        });

        meta.create_gate("MiMC5 Feistel last round", |meta| {
            let s = meta.query_selector(s_last_round);
            let prev_state_left = meta.query_advice(state_left, Rotation::prev());
            let prev_state_right = meta.query_advice(state_right, Rotation::prev());
            let current_state_left = meta.query_advice(state_left, Rotation::cur());
            let current_state_right = meta.query_advice(state_right, Rotation::cur());
            vec![
                s.clone()*(current_state_left - prev_state_left.clone()),
                s.clone()*(current_state_right - prev_state_right - pow_5_expr(prev_state_left)),
            ]
        });

        MiMC5FeistelHashConfig {
            state_left,
            state_right,
            round_constants,
            s_inner_rounds,
            s_last_round,
        }
    }

    fn hash_message(
        &self,
        mut layouter: impl Layouter<F>,
        message_left: &AssignedCell<F, F>,
        message_right: &AssignedCell<F, F>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F,F>), Error> {
        let config = self.get_config();

        let round_constant_values = Self::get_round_constants();
        layouter.assign_region(
            || "MiMC5 Feistel table",
            |mut region| {

                let msg_cell_left =
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

                let pow_5 = |v: Value<F>| { v*v*v*v*v };

                let mut current_state_left = message_left.value().copied();
                let mut current_state_right = message_right.value().copied();

                let mut state_cell_left = msg_cell_left.clone();
                let state_cell_right;

                for i in 1..round_constant_values.len() { // i goes from 1 to 219
                    config.s_inner_rounds.enable(&mut region, i)?;
                    region.assign_fixed(
                        || format!("round constant {:?}", i),
                        config.round_constants,
                        i-1,
                        || Value::known(round_constant_values[i-1]) // i starts at 1
                    )?;

                    let temp = current_state_right + pow_5(current_state_left + Value::known(round_constant_values[i-1]));
                    current_state_right = current_state_left;
                    current_state_left = temp;
                    
                    state_cell_left =
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

                current_state_right = current_state_right + pow_5(current_state_left);
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

pub struct MiMC5FeistelHashPallasChip {
    config: MiMC5FeistelHashConfig
}

impl MiMC5FeistelHashChip<Fp> for MiMC5FeistelHashPallasChip {
    fn construct(config: MiMC5FeistelHashConfig) -> Self {
        Self {
            config,
        }
    }

    fn get_config(&self) -> &MiMC5FeistelHashConfig {
        &self.config
    }

    fn get_round_constants() -> Vec<Fp> {
        MIMC_FEISTEL_PALLAS_ROUND_CONSTANTS.to_vec()
    }
}

pub struct MiMC5FeistelHashVestaChip {
    config: MiMC5FeistelHashConfig
}

impl MiMC5FeistelHashChip<Fq> for MiMC5FeistelHashVestaChip {
    fn construct(config: MiMC5FeistelHashConfig) -> Self {
        Self {
            config,
        }
    }

    fn get_config(&self) -> &MiMC5FeistelHashConfig {
        &self.config
    }

    fn get_round_constants() -> Vec<Fq> {
        MIMC_FEISTEL_VESTA_ROUND_CONSTANTS.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::mimc_feistel::primitives::{mimc5_feistel_hash_pallas, mimc5_feistel_hash_vesta};

    use super::*;
    use halo2_proofs::{dev::MockProver, pasta::Fp, plonk::Circuit, circuit::SimpleFloorPlanner};

    #[derive(Debug, Clone)]
    struct MiMC5FeistelHashCircuitConfig {
        input : Column<Advice>,
        mimc_config: MiMC5FeistelHashConfig,
    }

    #[derive(Default)]
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

 
    #[test]
    fn test_mimc5_feistel_pallas_hash() {
        let k = 8;

        let msg_l = Fp::from(1);
        let msg_r = Fp::from(2);
        let mut output_l = msg_l;
        let mut output_r = msg_r;
        mimc5_feistel_hash_pallas(&mut output_l, &mut output_r);

        let circuit = MiMC5FeistelHashPallasCircuit {
            message_left: msg_l,
            message_right: msg_r,
            message_hash_left: output_l,
            message_hash_right: output_r,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

    }

    #[derive(Default)]
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

 
    #[test]
    fn test_mimc5_feistel_vesta_hash() {
        let k = 8;

        let msg_l = Fq::from(1);
        let msg_r = Fq::from(2);
        let mut output_l = msg_l;
        let mut output_r = msg_r;
        mimc5_feistel_hash_vesta(&mut output_l, &mut output_r);

        let circuit = MiMC5FeistelHashVestaCircuit {
            message_left: msg_l,
            message_right: msg_r,
            message_hash_left: output_l,
            message_hash_right: output_r,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

    }


    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_mimc5_feistel_pallas_hash() {
        use plotters::prelude::*;
        let k = 8;
        let root = BitMapBackend::new("mimc5-feistel-pallas-hash-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("MiMC Feistel Hash Layout", ("sans-serif", 60)).unwrap();

        let circuit = MiMC5FeistelHashPallasCircuit {
            message_left: Fp::zero(),
            message_right: Fp::zero(),
            message_hash_left: Fp::zero(),
            message_hash_right: Fp::zero(),
        };

        halo2_proofs::dev::CircuitLayout::default()
            .render(k, &circuit, &root)
            .unwrap();
    }
}