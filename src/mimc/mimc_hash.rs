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
pub struct MiMC5HashConfig {
    state: Column<Advice>,
    round_constants: Column<Fixed>,
    s_in_rounds: Selector,
}

pub trait MiMC5HashChip<F: FieldExt> {
    fn construct(config: MiMC5HashConfig) -> Self;

    fn get_round_constants() -> Vec<F>;

    fn get_config(&self) -> &MiMC5HashConfig;

    fn configure(
        meta: &mut ConstraintSystem<F>,
        state: Column<Advice>,
        round_constants: Column<Fixed>,
    ) -> MiMC5HashConfig {
        let s_in_rounds = meta.selector();

        meta.enable_equality(state);
        meta.enable_constant(round_constants);

        //  state                    | round_constants   | selector
        //  x0 = message             |     c0            | 
        //  x1 = (x0+c0)^5           |     c1            | s_in_rounds
        //  x2 = (x1+c1)^5           |     c2            | s_in_rounds
        //  x3 = (x2+c2)^5           |     c3            | s_in_rounds
        //  x4 = (x3+c3)^5           |     c4            | s_in_rounds
        //       :                   |     :             |     :      
        //       :                   |     c109          |     :      
        //  x110 = (x109+key+c109)^5 |                   | s_in_rounds


        meta.create_gate("MiMC5 hash rounds", |meta| {
            let s = meta.query_selector(s_in_rounds);
            let pow_5_expr = |v: Expression<F>| {
                 v.clone() * v.clone() * v.clone() * v.clone() * v
            };
            let prev_state = meta.query_advice(state, Rotation::prev());
            let rc = meta.query_fixed(round_constants, Rotation::prev());
            let current_state = meta.query_advice(state, Rotation::cur());
            vec![
                s.clone()*(current_state - pow_5_expr(prev_state +  rc)),
            ]
        });

        MiMC5HashConfig {
            state,
            round_constants,
            s_in_rounds,
        }
    }

    fn hash_message(
        &self,
        mut layouter: impl Layouter<F>,
        initial_value: F,
    ) -> Result<AssignedCell<F,F>, Error> {
        let config = self.get_config();

        let round_constant_values = Self::get_round_constants();

        layouter.assign_region(
            || "MiMC5 table",
            |mut region| {

                let msg_cell =
                region.assign_advice(
                    || "message to be hashed",
                    config.state,
                    0,
                    || Value::known(initial_value),
                )?;

                let pow_5 = |v: F| { v*v*v*v*v };

                let mut current_state = initial_value;
                let mut state_cell = msg_cell.clone();
                for i in 1..=round_constant_values.len() {
                    config.s_in_rounds.enable(&mut region, i)?;
                    region.assign_fixed(
                        || format!("round constant {:?}", i),
                        config.round_constants,
                        i-1,
                        || Value::known(round_constant_values[i-1]) // i starts at 1
                    )?;

                    current_state = pow_5(current_state + round_constant_values[i-1]);
                    
                    state_cell =
                    region.assign_advice(
                        || format!("round {:?} output", i),
                        config.state,
                        i,
                        || Value::known(current_state)
                    )?;
                }

                Ok(state_cell)
            }
        )
    }
}

pub struct MiMC5HashPallasChip {
    config: MiMC5HashConfig
}

impl MiMC5HashChip<Fp> for MiMC5HashPallasChip {
    fn construct(config: MiMC5HashConfig) -> Self {
        Self {
            config,
        }
    }

    fn get_config(&self) -> &MiMC5HashConfig {
        &self.config
    }

    fn get_round_constants() -> Vec<Fp> {
        MIMC_HASH_PALLAS_ROUND_CONSTANTS.to_vec()
    }
}

pub struct MiMC5HashVestaChip {
    config: MiMC5HashConfig
}

impl MiMC5HashChip<Fq> for MiMC5HashVestaChip {
    fn construct(config: MiMC5HashConfig) -> Self {
        Self {
            config,
        }
    }

    fn get_config(&self) -> &MiMC5HashConfig {
        &self.config
    }

    fn get_round_constants() -> Vec<Fq> {
        MIMC_HASH_VESTA_ROUND_CONSTANTS.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::mimc::primitives::mimc5_hash;

    use super::*;
    use halo2_proofs::{dev::MockProver, pasta::Fp, plonk::Circuit, circuit::SimpleFloorPlanner};
    use crate::mimc::round_constants::{NUM_ROUNDS, MIMC_HASH_PALLAS_ROUND_CONSTANTS, MIMC_HASH_VESTA_ROUND_CONSTANTS};

    #[derive(Default)]
    struct MiMC5HashPallasCircuit {
        pub message: Fp,
        pub message_hash: Fp,
    }

    impl Circuit<Fp> for MiMC5HashPallasCircuit {
        type Config = MiMC5HashConfig;
        type FloorPlanner = SimpleFloorPlanner;
        
        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let state = meta.advice_column();
            let round_constants = meta.fixed_column();
            MiMC5HashPallasChip::configure(meta, state, round_constants)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = MiMC5HashPallasChip::construct(config.clone());

            let msg_hash = chip.hash_message(
                layouter.namespace(|| "entire table"),
                self.message,
            )?;

            layouter.assign_region(
                || "constrain output", 
                |mut region| {
                    let expected_output = region.assign_advice(
                        || "load output", 
                        config.state,
                        0,
                        || Value::known(self.message_hash),
                    )?;
                    region.constrain_equal(msg_hash.cell(), expected_output.cell())
                }
            )?;

            Ok(())
        }
    }

 
    #[test]
    fn test_mimc5_pallas_hash() {
        let k = 7;

        let msg = Fp::from(0);
        let mut output = msg;
        mimc5_hash::<Fp, { NUM_ROUNDS }>(&mut output, MIMC_HASH_PALLAS_ROUND_CONSTANTS);

        let circuit = MiMC5HashPallasCircuit {
            message: msg,
            message_hash: output,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

    }

    #[derive(Default)]
    struct MiMC5HashVestaCircuit {
        pub message: Fq,
        pub message_hash: Fq,
    }

    impl Circuit<Fq> for MiMC5HashVestaCircuit {
        type Config = MiMC5HashConfig;
        type FloorPlanner = SimpleFloorPlanner;
        
        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            let state = meta.advice_column();
            let round_constants = meta.fixed_column();
            MiMC5HashVestaChip::configure(meta, state, round_constants)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), Error> {
            let chip = MiMC5HashVestaChip::construct(config.clone());

            let msg_hash = chip.hash_message(
                layouter.namespace(|| "entire table"),
                self.message,
            )?;

            layouter.assign_region(
                || "constrain output", 
                |mut region| {
                    let expected_output = region.assign_advice(
                        || "load output", 
                        config.state,
                        0,
                        || Value::known(self.message_hash),
                    )?;
                    region.constrain_equal(msg_hash.cell(), expected_output.cell())
                }
            )?;

            Ok(())
        }
    }

     
    #[test]
    fn test_mimc5_vesta_hash() {
        let k = 7;

        let msg = Fq::from(0);
        let mut output = msg;
        mimc5_hash::<Fq, { NUM_ROUNDS }>(&mut output, MIMC_HASH_VESTA_ROUND_CONSTANTS);

        let circuit = MiMC5HashVestaCircuit {
            message: msg,
            message_hash: output,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

    }


    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_mimc5_pallas_hash() {
        use plotters::prelude::*;
        let k = 7;
        let root = BitMapBackend::new("mimc5-pallas-hash-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("MiMC Hash Layout", ("sans-serif", 60)).unwrap();

        let circuit = MiMC5HashPallasCircuit {
            message: Fp::zero(),
            message_hash: Fp::zero(),
        };

        halo2_proofs::dev::CircuitLayout::default()
            .render(k, &circuit, &root)
            .unwrap();
    }
}