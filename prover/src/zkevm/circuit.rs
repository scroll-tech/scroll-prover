use halo2_proofs::halo2curves::bn256::Fr;
use once_cell::sync::Lazy;
use snark_verifier_sdk::CircuitExt;
use types::eth::BlockTrace;
use zkevm_circuits::witness;

mod builder;
mod super_circuit;
pub use super_circuit::SuperCircuit;

use crate::utils::read_env_var;

pub use self::builder::{
    block_traces_to_padding_witness_block, block_traces_to_witness_block,
    block_traces_to_witness_block_with_updated_state, calculate_row_usage_of_trace,
    calculate_row_usage_of_witness_block, check_batch_capacity, 
    normalize_withdraw_proof, WitnessBlock, global_circuit_params,
    SUB_CIRCUIT_NAMES,
};

static CHAIN_ID: Lazy<u64> = Lazy::new(|| read_env_var("CHAIN_ID", 53077));
static AUTO_TRUNCATE: Lazy<bool> = Lazy::new(|| read_env_var("AUTO_TRUNCATE", false));

/// A target circuit trait is a wrapper of inner circuit, with convenient APIs for building
/// circuits from traces.
pub trait TargetCircuit {
    /// The actual inner circuit that implements Circuit trait.
    type Inner: CircuitExt<Fr>;

    /// Name tag of the circuit.
    /// This tag will be used as a key to index the circuit.
    /// It is therefore important that the name is unique.
    fn name() -> String;

    /// Generate a dummy circuit with an empty trace.
    /// This is useful for generating vk and pk.
    fn dummy_inner_circuit() -> Self::Inner
    where
        Self: Sized,
    {
        Self::from_block_traces(&[]).unwrap().0
    }

    /// Build the inner circuit and the instances from a traces
    fn from_block_trace(block_trace: &BlockTrace) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        Self::from_block_traces(std::slice::from_ref(block_trace))
    }

    /// Build the inner circuit and the instances from a list of traces
    fn from_block_traces(block_traces: &[BlockTrace]) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let witness_block = block_traces_to_witness_block(block_traces)?;
        Self::from_witness_block(&witness_block)
    }

    /// Build the inner circuit and the instances from the witness block
    fn from_witness_block(
        witness_block: &witness::Block<Fr>,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized;

    fn estimate_rows(block_traces: &[BlockTrace]) -> anyhow::Result<usize> {
        let witness_block = block_traces_to_witness_block(block_traces)?;
        Ok(Self::estimate_rows_from_witness_block(&witness_block))
    }

    fn estimate_rows_from_witness_block(_witness_block: &witness::Block<Fr>) -> usize {
        0
    }

    fn public_input_len() -> usize {
        0
    }
}
