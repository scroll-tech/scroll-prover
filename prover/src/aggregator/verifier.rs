use crate::{common, Proof};
use aggregator::CompressionCircuit;
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier_sdk::verify_snark_shplonk;

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

    pub fn from_params_dir(params_dir: &str, degree: u32, vk: Option<Vec<u8>>) -> Self {
        common::Verifier::from_params_dir(params_dir, degree, vk).into()
    }

    pub fn verify_agg_proof(&self, proof: Proof) -> Result<bool> {
        let vk = match self.inner.vk() {
            Some(vk) => vk,
            None => panic!("Aggregation verification key is missing"),
        };

        Ok(verify_snark_shplonk::<CompressionCircuit>(
            self.inner.params(),
            proof.to_snark(),
            vk,
        ))
    }
}
