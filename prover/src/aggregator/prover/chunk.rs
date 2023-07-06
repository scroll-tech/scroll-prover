use super::Prover;
use crate::{
    utils::{gen_rng, metric_of_witness_block},
    zkevm::circuit::TargetCircuit,
};
use anyhow::Result;
use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::{gen_snark_shplonk, Snark};
use zkevm_circuits::evm_circuit::witness::Block;

impl Prover {
    pub fn gen_chunk_snark<C: TargetCircuit>(
        &mut self,
        witness_block: &Block<Fr>,
    ) -> Result<Snark> {
        log::info!(
            "Proving the chunk: {:?}",
            metric_of_witness_block(witness_block)
        );

        let (circuit, _instance) = C::from_witness_block(witness_block)?;
        log::info!("Create {} proof", C::name());

        let (params, pk) = self.inner_params_and_pk::<C>(&C::dummy_inner_circuit())?;

        // Generate the SNARK proof for inner circuit.
        let snark = gen_snark_shplonk(params, pk, circuit, &mut gen_rng(), None::<String>);

        Ok(snark)
    }
}
