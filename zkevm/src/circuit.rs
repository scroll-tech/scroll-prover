use anyhow::bail;

use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::Circuit as Halo2Circuit;

use once_cell::sync::Lazy;

use types::eth::BlockTrace;

use zkevm_circuits::evm_circuit::EvmCircuit as EvmCircuitImpl;
use zkevm_circuits::mpt_circuit::MptCircuit as ZktrieCircuitImpl;
use zkevm_circuits::poseidon_circuit::PoseidonCircuit as PoseidonCircuitImpl;
use zkevm_circuits::state_circuit::StateCircuit as StateCircuitImpl;
use zkevm_circuits::super_circuit::SuperCircuit as SuperCircuitImpl;
use zkevm_circuits::util::SubCircuit;
use zkevm_circuits::witness;

mod builder;

use crate::utils::read_env_var;

pub use self::builder::{
    block_traces_to_witness_block, calculate_row_usage_of_trace,
    calculate_row_usage_of_witness_block, check_batch_capacity, SUB_CIRCUIT_NAMES,
};

////// params for degree = 19 ////////////
/*
pub static DEGREE: Lazy<usize> = Lazy::new(|| read_env_var("DEGREE", 19));
const MAX_TXS: usize = 44;
const MAX_INNER_BLOCKS: usize = 100;
const MAX_CALLDATA: usize = 400_000;
const MAX_RWS: usize = 500_000;
const MAX_KECCAK_ROWS: usize = 524_000;
const MAX_EXP_STEPS: usize = 10_000;
*/

////// params for degree = 20 ////////////
pub static DEGREE: Lazy<usize> = Lazy::new(|| read_env_var("DEGREE", 20));
const MAX_TXS: usize = 44;
const MAX_INNER_BLOCKS: usize = 100;
const MAX_CALLDATA: usize = 400_000;
const MAX_RWS: usize = 1_000_000;
const MAX_KECCAK_ROWS: usize = 524_000;
const MAX_EXP_STEPS: usize = 10_000;

pub static CHAIN_ID: Lazy<u64> = Lazy::new(|| read_env_var("CHAIN_ID", 0x82751));
pub static AGG_DEGREE: Lazy<usize> = Lazy::new(|| read_env_var("AGG_DEGREE", 26));
pub static AUTO_TRUNCATE: Lazy<bool> = Lazy::new(|| read_env_var("AUTO_TRUNCATE", true));

pub trait TargetCircuit {
    type Inner: Halo2Circuit<Fr>;
    fn name() -> String;
    /// used to generate vk&pk
    fn empty() -> Self::Inner
    where
        Self: Sized,
    {
        Self::from_block_traces(&[]).unwrap().0
    }
    fn from_block_trace(block_trace: &BlockTrace) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        Self::from_block_traces(std::slice::from_ref(block_trace))
    }
    fn from_block_traces(block_traces: &[BlockTrace]) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let witness_block = block_traces_to_witness_block(block_traces)?;
        Self::from_witness_block(&witness_block)
    }
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

pub struct SuperCircuit {}

impl TargetCircuit for SuperCircuit {
    type Inner = SuperCircuitImpl<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, 0x1000>;

    fn name() -> String {
        "super".to_string()
    }

    fn from_witness_block(
        witness_block: &witness::Block<Fr>,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let (k, inner, instance) = Self::Inner::build_from_witness_block(witness_block.clone())?;
        if k as usize > *DEGREE {
            bail!(
                "circuit not enough: DEGREE = {}, less than k needed: {}",
                *DEGREE,
                k
            );
        }
        Ok((inner, instance))
    }

    fn estimate_rows_from_witness_block(witness_block: &witness::Block<Fr>) -> usize {
        Self::Inner::min_num_rows_block(witness_block).1
    }

    fn public_input_len() -> usize {
        1
    }
}

pub struct EvmCircuit {}

impl TargetCircuit for EvmCircuit {
    type Inner = EvmCircuitImpl<Fr>;

    fn name() -> String {
        "evm".to_string()
    }

    fn from_witness_block(
        witness_block: &witness::Block<Fr>,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let inner = EvmCircuitImpl::<Fr>::new(witness_block.clone());
        let instance = vec![];
        Ok((inner, instance))
    }
}

pub struct StateCircuit {}
impl TargetCircuit for StateCircuit {
    type Inner = StateCircuitImpl<Fr>;

    fn name() -> String {
        "state".to_string()
    }

    // TODO: use from_block_trace(&Default::default()) ?
    fn empty() -> Self::Inner {
        StateCircuitImpl::<Fr>::default()
    }

    fn from_witness_block(
        witness_block: &witness::Block<Fr>,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let inner = StateCircuitImpl::<Fr>::new(
            witness_block.rws.clone(),
            // TODO: put it into CircuitParams?
            (1 << *DEGREE) - 64,
        );
        let instance = vec![];
        Ok((inner, instance))
    }
}

/*
fn trie_data_from_blocks<'d>(
    block_traces: impl IntoIterator<Item = &'d BlockTrace>,
) -> EthTrie<Fr> {
    let mut trie_data: EthTrie<Fr> = Default::default();
    let mut total_tx_num = 0usize;
    for (idx, block_trace) in block_traces.into_iter().enumerate() {
        let storage_ops: Vec<AccountOp<_>> = block_trace
            .mpt_witness
            .iter()
            .map(|tr| tr.try_into().unwrap())
            .collect();
        trie_data.add_ops(storage_ops);
        total_tx_num += block_trace.execution_results.len();
        log::debug!(
            "after {}th block(tx num: {}), total tx num: {}, zktrie row num: {:?}",
            idx,
            block_trace.transactions.len(),
            total_tx_num,
            trie_data.use_rows()
        );
    }

    trie_data
}
*/

pub struct ZktrieCircuit {}

impl TargetCircuit for ZktrieCircuit {
    type Inner = ZktrieCircuitImpl<Fr>;

    fn name() -> String {
        "zktrie".to_string()
    }

    fn from_witness_block(
        witness_block: &witness::Block<Fr>,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let inner = ZktrieCircuitImpl::new_from_block(witness_block);
        let instance = vec![];
        Ok((inner, instance))
    }
}

pub struct PoseidonCircuit {}

impl TargetCircuit for PoseidonCircuit {
    type Inner = PoseidonCircuitImpl<Fr>;

    fn name() -> String {
        "poseidon".to_string()
    }

    fn from_witness_block(
        witness_block: &witness::Block<Fr>,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let inner = PoseidonCircuitImpl::new_from_block(witness_block);
        let instance = vec![];
        Ok((inner, instance))
    }
}
