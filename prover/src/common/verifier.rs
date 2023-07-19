use crate::{utils::load_params, Proof};
use aggregator::CompressionCircuit;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};
use snark_verifier_sdk::{verify_snark_shplonk, CircuitExt};
use std::io::Cursor;

mod evm;
mod utils;

#[derive(Debug)]
pub struct Verifier {
    params: ParamsKZG<Bn256>,
    vk: VerifyingKey<G1Affine>,
}

impl Verifier {
    pub fn new(params: ParamsKZG<Bn256>, vk: VerifyingKey<G1Affine>) -> Self {
        Self { params, vk }
    }

    pub fn from_params(params: ParamsKZG<Bn256>, raw_vk: &[u8]) -> Self {
        let vk = VerifyingKey::<G1Affine>::read::<_, CompressionCircuit>(
            &mut Cursor::new(raw_vk),
            SerdeFormat::Processed,
        )
        .unwrap();

        Self { params, vk }
    }

    pub fn from_params_dir(params_dir: &str, degree: u32, vk: &[u8]) -> Self {
        let params = load_params(params_dir, degree, None).unwrap();

        Self::from_params(params, vk)
    }

    pub fn verify_proof<C: CircuitExt<Fr>>(&self, proof: Proof) -> bool {
        verify_snark_shplonk::<C>(&self.params, proof.to_snark(), &self.vk)
    }
}
