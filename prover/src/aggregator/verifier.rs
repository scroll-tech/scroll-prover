use crate::{common, config::LAYER4_DEGREE, Proof};
use aggregator::CompressionCircuit;
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};

#[derive(Debug)]
pub struct Verifier {
    inner: common::Verifier,
}

impl From<common::Verifier> for Verifier {
    fn from(inner: common::Verifier) -> Self {
        Self { inner }
    }
}

impl Verifier {
    pub fn new(params: ParamsKZG<Bn256>, vk: Option<VerifyingKey<G1Affine>>) -> Self {
        common::Verifier::new(params, vk).into()
    }

    pub fn from_params(params: ParamsKZG<Bn256>, raw_vk: Option<Vec<u8>>) -> Self {
        common::Verifier::from_params(params, raw_vk).into()
    }

    pub fn from_params_dir(params_dir: &str, vk: Option<Vec<u8>>) -> Self {
        common::Verifier::from_params_dir(params_dir, *LAYER4_DEGREE, vk).into()
    }

    pub fn verify_agg_proof(&self, proof: Proof) -> Result<bool> {
        self.inner.verify_proof::<CompressionCircuit>(proof)
    }
}
