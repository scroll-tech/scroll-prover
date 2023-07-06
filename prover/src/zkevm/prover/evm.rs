use super::Prover;
use halo2_proofs::{halo2curves::bn256::G1Affine, plonk::VerifyingKey};
use snark_verifier_sdk::{gen_evm_verifier_shplonk, AggregationCircuit, CircuitExt};
use std::path::Path;

impl Prover {
    /// Generate the EVM bytecode for plonk verifier.
    pub fn create_evm_verifier_bytecode(
        &self,
        agg_circuit: &AggregationCircuit,
        agg_vk: &VerifyingKey<G1Affine>,
        path: Option<&Path>,
    ) -> Vec<u8> {
        gen_evm_verifier_shplonk::<AggregationCircuit>(
            &self.chunk_params,
            agg_vk,
            agg_circuit.num_instance(),
            path,
        )
    }
}
