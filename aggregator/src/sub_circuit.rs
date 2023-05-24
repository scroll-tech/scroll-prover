use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};

use super::{circuit::BatchHashCircuit, config::BatchCircuitConfig, LOG_DEGREE};
use zkevm_circuits::util::{Challenges, SubCircuit};
use zkevm_circuits::witness::Block;

impl<F: Field> SubCircuit<F> for BatchHashCircuit<F> {
    type Config = BatchCircuitConfig<F>;

    fn new_from_block(_block: &Block<F>) -> Self {
        // we cannot instantiate a new Self from a single block
        unimplemented!()
    }

    /// Return the minimum number of rows required to prove the block
    /// Row numbers without/with padding are both returned.
    fn min_num_rows_block(_block: &Block<F>) -> (usize, usize) {
        (1 << LOG_DEGREE, 1 << LOG_DEGREE)
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        let public_input = self.public_input();

        let first_chunk_prev_state_root = public_input
            .first_chunk_prev_state_root
            .as_bytes()
            .iter()
            .map(|&x| F::from(x as u64));

        let last_chunk_post_state_root = public_input
            .last_chunk_post_state_root
            .as_bytes()
            .iter()
            .map(|&x| F::from(x as u64));

        let last_chunk_withdraw_root = public_input
            .last_chunk_withdraw_root
            .as_bytes()
            .iter()
            .map(|&x| F::from(x as u64));

        let batch_public_input_hash = public_input
            .batch_public_input_hash
            .as_bytes()
            .iter()
            .map(|&x| F::from(x as u64));

        vec![first_chunk_prev_state_root
            .chain(last_chunk_post_state_root)
            .chain(last_chunk_withdraw_root)
            .chain(batch_public_input_hash)
            .collect()]
    }

    /// Make the assignments to the PiCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
