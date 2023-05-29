use eth_types::Field;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Error;
use halo2_proofs::{
    circuit::SimpleFloorPlanner,
    plonk::{Circuit, ConstraintSystem, Expression},
};
use zkevm_circuits::util::{Challenges, SubCircuit, SubCircuitConfig};

use crate::{BatchCircuitConfig, BatchCircuitConfigArgs, BatchHashCircuit};

#[derive(Debug, Clone)]
pub struct SuperAggregationCircuitConfig<F: Field> {
    batch_circuit_public_input_config: BatchCircuitConfig<F>,
}

pub struct SuperAggregationCircuitConfigArgs<F: Field> {
    pub challenges: Challenges<Expression<F>>,
}

#[derive(Debug, Clone, Default)]
/// Super circuit for aggregation circuit
pub struct SuperAggregationCircuit<F: Field> {
    batch_hash_circuit: BatchHashCircuit<F>,
}

impl<F: Field> Circuit<F> for SuperAggregationCircuit<F> {
    type Config = (SuperAggregationCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);

        let batch_circuit_config_args = BatchCircuitConfigArgs {
            challenges: challenge_exprs,
        };
        let batch_circuit_public_input_config =
            BatchCircuitConfig::new(meta, batch_circuit_config_args);

        todo!()
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        self.batch_hash_circuit.synthesize_sub(
            &config.batch_circuit_public_input_config,
            &challenges,
            &mut layouter,
        )?;

        // todo: synthesize sub for super circuit
        Ok(())
    }
}
