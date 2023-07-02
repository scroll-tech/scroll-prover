use crate::Proof;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier_sdk::{evm_verify, gen_evm_verifier, CircuitExt};
use std::path::Path;

#[derive(Debug)]
pub struct Verifier {
    params: ParamsKZG<Bn256>,
}

impl Verifier {
    pub fn from_params(params: ParamsKZG<Bn256>) -> Self {
        Self { params }
    }

    // Should panic if failed to verify.
    pub fn evm_verify<C: CircuitExt<Fr>>(&self, proof: &Proof, yul_file_path: Option<&Path>) {
        let vk = proof.vk::<C>().expect("Failed to get vk");
        let num_instance = proof.num_instance().expect("Not a EVM proof").clone();

        let deployment_code = gen_evm_verifier::<C, Kzg<Bn256, Bdfg21>>(
            &self.params,
            &vk,
            num_instance,
            yul_file_path,
        );

        evm_verify(deployment_code, proof.instances(), proof.proof().to_vec());
    }
}
