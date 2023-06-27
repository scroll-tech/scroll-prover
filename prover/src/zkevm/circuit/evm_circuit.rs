
use super::{TargetCircuit, DEGREE};

use anyhow::bail;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::witness;
use zkevm_circuits::util::SubCircuit;

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