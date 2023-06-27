use super::{TargetCircuit, DEGREE};

use super::{MAX_CALLDATA, MAX_INNER_BLOCKS, MAX_TXS};
use anyhow::bail;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::util::SubCircuit;
use zkevm_circuits::{super_circuit::SuperCircuit as SuperCircuitTpl, witness};

type SuperCircuitImpl = SuperCircuitTpl<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, 0x1000>;

pub struct SuperCircuit {}

impl TargetCircuit for SuperCircuit {
    type Inner = SuperCircuitImpl;

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
