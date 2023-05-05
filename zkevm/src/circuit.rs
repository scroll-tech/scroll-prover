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
    block_traces_to_witness_block, calculate_row_usage_of_trace,
    calculate_row_usage_of_witness_block, check_batch_capacity, SUB_CIRCUIT_NAMES,
};

////// params for degree = 19 ////////////
/*
pub static DEGREE: Lazy<usize> = Lazy::new(|| read_env_var("DEGREE", 19));
const MAX_INNER_BLOCKS: usize = 100;
const MAX_CALLDATA: usize = 400_000;
const MAX_RWS: usize = 500_000;
const MAX_KECCAK_ROWS: usize = 524_000;
const MAX_EXP_STEPS: usize = 10_000;
*/

////// params for degree = 20 ////////////
pub static DEGREE: Lazy<usize> = Lazy::new(|| read_env_var("DEGREE", 20));
const MAX_TXS: usize = 32;
const MAX_INNER_BLOCKS: usize = 100;
const MAX_EXP_STEPS: usize = 10_000;
const MAX_CALLDATA: usize = 400_000;
const MAX_BYTECODE: usize = 400_000;
const MAX_MPT_ROWS: usize = 400_000;
const MAX_KECCAK_ROWS: usize = 524_000;
const MAX_RWS: usize = 1_000_000;

pub static CHAIN_ID: Lazy<u64> = Lazy::new(|| read_env_var("CHAIN_ID", 0x82751));
pub static AGG_DEGREE: Lazy<usize> = Lazy::new(|| read_env_var("AGG_DEGREE", 26));
pub static AUTO_TRUNCATE: Lazy<bool> = Lazy::new(|| read_env_var("AUTO_TRUNCATE", true));

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
