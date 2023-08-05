use crate::{
    common,
    config::{LAYER2_CONFIG_PATH, LAYER2_DEGREE},
    io::read_all,
    utils::read_env_var,
    ChunkProof,
};
use aggregator::CompressionCircuit;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use once_cell::sync::Lazy;
use std::{env, path::Path};

static CHUNK_VK_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("CHUNK_VK_FILENAME", "chunk_vk.vkey".to_string()));

#[derive(Debug)]
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

    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        let vk_path = format!("{assets_dir}/{}", *CHUNK_VK_FILENAME);
        if !Path::new(&vk_path).exists() {
            panic!("File {vk_path} must exist");
        }

        let raw_vk = read_all(&vk_path);

        env::set_var("COMPRESSION_CONFIG", &*LAYER2_CONFIG_PATH);
        common::Verifier::from_params_dir(params_dir, *LAYER2_DEGREE, &raw_vk).into()
    }

    pub fn verify_chunk_proof(&self, proof: ChunkProof) -> bool {
        self.inner.verify_snark(proof.to_snark())
    }
}
