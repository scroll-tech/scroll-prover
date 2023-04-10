
use super::{TargetCircuit, DEGREE};

use anyhow::bail;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::witness;
use zkevm_circuits::util::SubCircuit;

pub struct StateCircuit {}
impl TargetCircuit for StateCircuit {
    type Inner = StateCircuitImpl<Fr>;

    fn name() -> String {
        "state".to_string()
    }

    // TODO: use from_block_trace(&Default::default()) ?
    fn dummy_inner_circuit() -> Self::Inner {
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
