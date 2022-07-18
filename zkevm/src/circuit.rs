use bus_mapping::operation::OperationContainer;

use mpt_circuits::{EthTrie, EthTrieCircuit, HashCircuit, operation::AccountOp, hash::Hashable};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::pairing::bn256::Fr;
//use halo2_proofs::pairing::group::ff::PrimeField;
use halo2_proofs::plonk::Circuit as Halo2Circuit;

use once_cell::sync::Lazy;

use strum::IntoEnumIterator;
use types::eth::BlockResult;
use zkevm_circuits::evm_circuit::table::FixedTableTag;
use zkevm_circuits::evm_circuit::test::TestCircuit;
use zkevm_circuits::evm_circuit::witness::{Block, RwMap};
use zkevm_circuits::state_circuit::StateCircuitLight as StateCircuitImpl;

mod builder;

use crate::circuit::builder::get_fixed_table_tags_for_block;
use crate::utils::read_env_var;

use self::builder::block_result_to_witness_block;

pub static DEGREE: Lazy<usize> = Lazy::new(|| read_env_var("DEGREE", 18));
pub static AGG_DEGREE: Lazy<usize> = Lazy::new(|| read_env_var("AGG_DEGREE", 26));

pub trait TargetCircuit {
    type Inner : Halo2Circuit<Fr>;
    fn name() -> String;
    fn empty() -> Self::Inner;
    //fn public_input_len() -> usize { 0 }
    fn from_block_result(block_result: &BlockResult) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized;
}

pub struct EvmCircuit {}

impl TargetCircuit for EvmCircuit {

    type Inner = TestCircuit<Fr>;

    fn name() -> String {
        "evm".to_string()
    }

    fn empty() -> Self::Inner {
        let default_block = Block::<Fr> {
            pad_to: (1 << *DEGREE) - 64,
            ..Default::default()
        };

        // hack but useful
        let tags = if *DEGREE <= 16 {
            log::warn!("create_evm_circuit() may skip fixed bitwise table");
            get_fixed_table_tags_for_block(&default_block)
        } else {
            FixedTableTag::iter().collect()
        };

        TestCircuit::new(default_block, tags)
    }

    fn from_block_result(
        block_result: &BlockResult,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let witness_block = block_result_to_witness_block::<Fr>(block_result)?;
        let inner = TestCircuit::<Fr>::new(witness_block, FixedTableTag::iter().collect());
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

    fn empty() -> Self::Inner {
        let rw_map = RwMap::from(&OperationContainer {
            memory: vec![],
            stack: vec![],
            storage: vec![],
            ..Default::default()
        });

        // same with https://github.com/scroll-tech/zkevm-circuits/blob/fceb61d0fb580a04262ebd3556dbc0cab15d16c4/zkevm-circuits/src/util.rs#L75
        const DEFAULT_RAND: u128 = 0x10000;
        StateCircuitImpl::<Fr>::new(Fr::from_u128(DEFAULT_RAND), rw_map)
    }

    fn from_block_result(
        block_result: &BlockResult,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let witness_block = block_result_to_witness_block::<Fr>(block_result)?;
        let inner = StateCircuitImpl::<Fr>::new(witness_block.randomness, witness_block.rws);
        let instance = vec![];
        Ok((inner, instance))
    }
}

fn mpt_rows() -> usize { (*DEGREE - 10) / <Fr as Hashable>::hash_block_size()}

pub struct ZktrieCircuit {}

impl TargetCircuit for ZktrieCircuit {

    type Inner = EthTrieCircuit<Fr>;

    fn name() -> String {
        "zktrie".to_string()
    }
    fn empty() -> Self::Inner {
        let dummy_trie : EthTrie<Fr> = Default::default();
        let (circuit, _) = dummy_trie.circuits(mpt_rows());
        circuit
    }
    fn from_block_result(block_result: &BlockResult) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let storage_ops: Vec<AccountOp<_>> = block_result.mpt_witness.iter().map(|tr| tr.try_into().unwrap()).collect();
        let mut trie_data: EthTrie<Fr> = Default::default();
        trie_data.add_ops(storage_ops);
        let (mpt_circuit, _) = trie_data.circuits(mpt_rows());
        let instance = vec![];
        Ok((mpt_circuit, instance))
    }
}

pub struct PoseidonCircuit {}

impl TargetCircuit for PoseidonCircuit {

    type Inner = HashCircuit<Fr>;

    fn name() -> String {
        "poseidon".to_string()
    }
    fn empty() -> Self::Inner {
        let dummy_trie : EthTrie<Fr> = Default::default();
        let (_, circuit) = dummy_trie.circuits(mpt_rows());
        circuit
    }
    fn from_block_result(
        block_result: &BlockResult,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let storage_ops: Vec<AccountOp<_>> = block_result.mpt_witness.iter().map(|tr| tr.try_into().unwrap()).collect();
        let mut trie_data: EthTrie<Fr> = Default::default();
        trie_data.add_ops(storage_ops);
        let (_, circuit) = trie_data.circuits(mpt_rows());
        let instance = vec![];
        Ok((circuit, instance))
    }
}
