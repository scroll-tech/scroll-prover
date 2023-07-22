use crate::{common, config::LAYER2_DEGREE, Proof};
use aggregator::CompressionCircuit;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use std::env::set_var;

pub struct Verifier {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub inner: common::Verifier<CompressionCircuit>,
}

impl From<common::Verifier<CompressionCircuit>> for Verifier {
    fn from(inner: common::Verifier<CompressionCircuit>) -> Self {
        Self { inner }
    }
}

impl Verifier {
    pub fn new(params: ParamsKZG<Bn256>, vk: VerifyingKey<G1Affine>) -> Self {
        common::Verifier::new(params, vk).into()
    }

    pub fn from_params_dir(params_dir: &str, vk: &[u8]) -> Self {
        set_var("COMPRESSION_CONFIG", "./configs/layer2.config");

        common::Verifier::from_params_dir(params_dir, *LAYER2_DEGREE, vk).into()
    }

    pub fn verify_chunk_proof(&self, proof: Proof) -> bool {
        self.inner.verify_proof(proof)
    }
}
