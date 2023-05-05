use super::Prover;
use halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_proofs::plonk::VerifyingKey;
use snark_verifier_sdk::evm::gen_evm_verifier_shplonk;
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::CircuitExt;
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
            &self.agg_params,
            agg_vk,
            agg_circuit.num_instance(),
            path,
        )
    }
}
