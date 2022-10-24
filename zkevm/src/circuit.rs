use bus_mapping::operation::OperationContainer;

use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::Circuit as Halo2Circuit;

use mpt_circuits::{hash::Hashable, operation::AccountOp, EthTrie, EthTrieCircuit, HashCircuit};

use once_cell::sync::Lazy;

use strum::IntoEnumIterator;
use types::eth::BlockResult;
use zkevm_circuits::evm_circuit::table::FixedTableTag;
use zkevm_circuits::evm_circuit::test::TestCircuit as EvmTestCircuit;
use zkevm_circuits::evm_circuit::witness::{Block, RwMap};
use zkevm_circuits::state_circuit::StateCircuit as StateCircuitImpl;

mod builder;
mod mpt;

use crate::circuit::builder::get_fixed_table_tags_for_block;
use crate::utils::read_env_var;

use self::builder::{block_result_to_witness_block, block_results_to_witness_block};

pub static DEGREE: Lazy<usize> = Lazy::new(|| read_env_var("DEGREE", 18));
pub static AGG_DEGREE: Lazy<usize> = Lazy::new(|| read_env_var("AGG_DEGREE", 25));

pub trait TargetCircuit {
    type Inner: Halo2Circuit<Fr>;
    fn name() -> String;
    /// used to generate vk&pk
    fn empty() -> Self::Inner;
    //fn public_input_len() -> usize { 0 }
    fn from_block_result(block_result: &BlockResult) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized;
    fn from_block_results(
        block_results: &[BlockResult],
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        log::error!(
            "from_block_results for circuit {} unimplemented, use first block result",
            Self::name()
        );
        Self::from_block_result(&block_results[0])
    }

    fn estimate_rows(_block_result: &BlockResult) -> usize {
        0
    }
    fn public_input_len() -> usize {
        0
    }
    fn get_active_rows(block_result: &BlockResult) -> (Vec<usize>, Vec<usize>) {
        (
            (0..Self::estimate_rows(block_result)).into_iter().collect(),
            (0..Self::estimate_rows(block_result)).into_iter().collect(),
        )
    }
}

pub struct EvmCircuit {}

impl TargetCircuit for EvmCircuit {
    type Inner = EvmTestCircuit<Fr>;

    fn name() -> String {
        "evm".to_string()
    }

    fn empty() -> Self::Inner {
        let default_block = Block::<Fr> {
            evm_circuit_pad_to: (1 << *DEGREE) - 64,
            ..Default::default()
        };

        // hack but useful
        let tags = if *DEGREE <= 16 {
            log::warn!("create_evm_circuit() may skip fixed bitwise table");
            get_fixed_table_tags_for_block(&default_block)
        } else {
            FixedTableTag::iter().collect()
        };

        EvmTestCircuit::new(default_block, tags)
    }

    fn from_block_result(block_result: &BlockResult) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let witness_block = block_result_to_witness_block(block_result)?;
        let inner = EvmTestCircuit::<Fr>::new(witness_block, FixedTableTag::iter().collect());
        let instance = vec![];
        Ok((inner, instance))
    }

    fn from_block_results(
        block_results: &[BlockResult],
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let witness_block = block_results_to_witness_block(block_results)?;
        let inner = EvmTestCircuit::<Fr>::new(witness_block, FixedTableTag::iter().collect());
        let instance = vec![];
        Ok((inner, instance))
    }

    fn estimate_rows(block_result: &BlockResult) -> usize {
        match block_result_to_witness_block(block_result) {
            Ok(witness_block) => EvmTestCircuit::<Fr>::get_num_rows_required(&witness_block),
            Err(e) => {
                log::error!("convert block result to witness block failed: {:?}", e);
                0
            }
        }
    }
}

pub struct StateCircuit {}
impl TargetCircuit for StateCircuit {
    type Inner = StateCircuitImpl<Fr>;

    fn name() -> String {
        "state".to_string()
    }

    // TODO: use from_block_result(&Default::default()) ?
    fn empty() -> Self::Inner {
        let rw_map = RwMap::from(&OperationContainer {
            memory: vec![],
            stack: vec![],
            storage: vec![],
            ..Default::default()
        });

        // same with https://github.com/scroll-tech/zkevm-circuits/blob/fceb61d0fb580a04262ebd3556dbc0cab15d16c4/zkevm-circuits/src/util.rs#L75
        const DEFAULT_RAND: u128 = 0x10000;
        StateCircuitImpl::<Fr>::new(Fr::from_u128(DEFAULT_RAND), rw_map, 0)
    }

    fn from_block_result(block_result: &BlockResult) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let witness_block = block_result_to_witness_block(block_result)?;
        let inner = StateCircuitImpl::<Fr>::new(
            witness_block.randomness,
            witness_block.rws,
            witness_block.state_circuit_pad_to,
        );
        let instance = vec![];
        Ok((inner, instance))
    }

    fn from_block_results(
        block_results: &[BlockResult],
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let witness_block = block_results_to_witness_block(block_results)?;
        let inner = StateCircuitImpl::<Fr>::new(
            witness_block.randomness,
            witness_block.rws,
            witness_block.state_circuit_pad_to,
        );
        let instance = vec![];
        Ok((inner, instance))
    }

    fn estimate_rows(block_result: &BlockResult) -> usize {
        let witness_block = block_result_to_witness_block(block_result).unwrap();
        1 + witness_block
            .rws
            .0
            .iter()
            .fold(0usize, |total, (_, v)| v.len() + total)
    }
    fn get_active_rows(block_result: &BlockResult) -> (Vec<usize>, Vec<usize>) {
        let witness_block = block_result_to_witness_block(block_result).unwrap();
        let rows = Self::estimate_rows(block_result);
        let active_rows: Vec<_> = (if witness_block.state_circuit_pad_to == 0 {
            0..rows
        } else {
            (witness_block.state_circuit_pad_to - rows)..witness_block.state_circuit_pad_to
        })
        .into_iter()
        .collect();
        (active_rows.clone(), active_rows)
    }
}

fn mpt_rows() -> usize {
    ((1 << *DEGREE) - 10) / <Fr as Hashable>::hash_block_size()
}

fn trie_data_from_blocks<'d>(
    block_results: impl IntoIterator<Item = &'d BlockResult>,
) -> EthTrie<Fr> {
    let mut trie_data: EthTrie<Fr> = Default::default();
    for block_result in block_results.into_iter() {
        let storage_ops: Vec<AccountOp<_>> = block_result
            .mpt_witness
            .iter()
            .map(|tr| tr.try_into().unwrap())
            .collect();
        trie_data.add_ops(storage_ops);
    }

    trie_data
}

pub struct ZktrieCircuit {}

impl TargetCircuit for ZktrieCircuit {
    type Inner = EthTrieCircuit<Fr>;

    fn name() -> String {
        "zktrie".to_string()
    }
    fn empty() -> Self::Inner {
        let dummy_trie: EthTrie<Fr> = Default::default();
        let (circuit, _) = dummy_trie.circuits(mpt_rows());
        circuit
    }

    fn from_block_results(
        block_results: &[BlockResult],
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let trie_data = trie_data_from_blocks(block_results);
        //        let (rows, _) = trie_data.use_rows();
        //        log::info!("zktrie use rows {}", rows);
        let (mpt_circuit, _) = trie_data.circuits(mpt_rows());
        let instance = vec![];
        Ok((mpt_circuit, instance))
    }

    fn from_block_result(block_result: &BlockResult) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let (mpt_circuit, _) = trie_data_from_blocks(Some(block_result)).circuits(mpt_rows());
        let instance = vec![];
        Ok((mpt_circuit, instance))
    }

    fn estimate_rows(block_result: &BlockResult) -> usize {
        let (mpt_rows, _) = trie_data_from_blocks(Some(block_result)).use_rows();
        mpt_rows
    }

    fn get_active_rows(block_result: &BlockResult) -> (Vec<usize>, Vec<usize>) {
        // we have compare and pick the maxium for lookup and gate rows, here we
        // just make sure it not less than 64 (so it has contained all constant rows)
        let ret = Self::estimate_rows(block_result);
        ((0..ret.max(64)).collect(), (0..ret.max(64)).collect())
    }
}

pub struct PoseidonCircuit {}

impl TargetCircuit for PoseidonCircuit {
    type Inner = HashCircuit<Fr>;

    fn name() -> String {
        "poseidon".to_string()
    }
    fn empty() -> Self::Inner {
        let dummy_trie: EthTrie<Fr> = Default::default();
        let (_, circuit) = dummy_trie.circuits(mpt_rows());
        circuit
    }

    fn from_block_results(
        block_results: &[BlockResult],
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let trie_data = trie_data_from_blocks(block_results);
        //        let (_, rows) = trie_data.use_rows();
        //        log::info!("poseidon use rows {}", rows);
        let (_, circuit) = trie_data.circuits(mpt_rows());
        let instance = vec![];
        Ok((circuit, instance))
    }

    fn from_block_result(block_result: &BlockResult) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let (_, circuit) = trie_data_from_blocks(Some(block_result)).circuits(mpt_rows());
        let instance = vec![];
        Ok((circuit, instance))
    }

    fn estimate_rows(block_result: &BlockResult) -> usize {
        let (_, rows) = trie_data_from_blocks(Some(block_result)).use_rows();
        rows
    }
}
