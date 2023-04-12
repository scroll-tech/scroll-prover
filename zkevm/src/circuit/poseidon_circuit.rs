

use super::{TargetCircuit, DEGREE};

use anyhow::bail;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::witness;
use zkevm_circuits::util::SubCircuit;

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