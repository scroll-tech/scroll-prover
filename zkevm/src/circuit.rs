use bus_mapping::operation::OperationContainer;

use halo2_mpt_circuits::EthTrie;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::pairing::group::ff::PrimeField;
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

pub trait TargetCircuit<Inner: Halo2Circuit<Fr>> {
    fn name() -> String;
    fn empty() -> Inner;
    //fn public_input_len() -> usize { 0 }
    fn from_block_result(block_result: &BlockResult) -> anyhow::Result<(Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized;
}

pub struct EvmCircuit {}

impl TargetCircuit<TestCircuit<Fr>> for EvmCircuit {
    fn name() -> String {
        "evm".to_string()
    }

    fn empty() -> TestCircuit<Fr> {
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
    ) -> anyhow::Result<(TestCircuit<Fr>, Vec<Vec<Fr>>)>
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
impl TargetCircuit<StateCircuitImpl<Fr>> for StateCircuit {
    fn name() -> String {
        "state".to_string()
    }

    fn empty() -> StateCircuitImpl<Fr> {
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
    ) -> anyhow::Result<(StateCircuitImpl<Fr>, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let witness_block = block_result_to_witness_block::<Fr>(block_result)?;
        let inner = StateCircuitImpl::<Fr>::new(witness_block.randomness, witness_block.rws);
        let instance = vec![];
        Ok((inner, instance))
    }
}

pub struct ZktrieCircuit {}

impl TargetCircuit<EthTrie<Fr>> for ZktrieCircuit {
    fn name() -> String {
        "zktrie".to_string()
    }
    fn empty() -> EthTrie<Fr> {
        halo2_mpt_circuits::EthTrie::<Fr>::new(10)
    }
    fn from_block_result(block_result: &BlockResult) -> anyhow::Result<(EthTrie<Fr>, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let _witness_block = block_result_to_witness_block::<Fr>(block_result)?;
        // TODO: weifan
        let inner = halo2_mpt_circuits::EthTrie::<Fr>::new(10);
        let instance = vec![];
        Ok((inner, instance))
    }
}

pub struct PoseidonCircuit {}

impl TargetCircuit<halo2_mpt_circuits::hash::HashCircuit<3>> for PoseidonCircuit {
    fn name() -> String {
        "poseidon".to_string()
    }
    fn empty() -> halo2_mpt_circuits::hash::HashCircuit<3> {
        let message1 = [
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
        ];
        let message2 = [
            Fr::from_str_vartime("0").unwrap(),
            Fr::from_str_vartime("1").unwrap(),
        ];

        halo2_mpt_circuits::hash::HashCircuit::<3> {
            inputs: [
                Some(message1),
                Some(message2),
                Some([Fr::one(), Fr::zero()]),
            ],
        }
    }
    fn from_block_result(
        block_result: &BlockResult,
    ) -> anyhow::Result<(halo2_mpt_circuits::hash::HashCircuit<3>, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let _witness_block = block_result_to_witness_block::<Fr>(block_result)?;
        // TODO: weifan
        let inner = Self::empty();
        let instance = vec![];
        Ok((inner, instance))
    }
}
