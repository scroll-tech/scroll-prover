use crate::{
    common,
    config::{LAYER4_CONFIG_PATH, LAYER4_DEGREE},
    io::read_all,
    utils::read_env_var,
    BatchProof,
};
use aggregator::CompressionCircuit;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use once_cell::sync::Lazy;
use snark_verifier_sdk::verify_evm_calldata;
use std::{env, path::Path};

static AGG_VK_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("AGG_VK_FILENAME", "agg_vk.vkey".to_string()));
static DEPLOYMENT_CODE_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("DEPLOYMENT_CODE_FILENAME", "evm_verifier.bin".to_string()));

#[derive(Debug)]
pub struct Verifier {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub inner: common::Verifier<CompressionCircuit>,
    deployment_code: Vec<u8>,
}

impl Verifier {
    pub fn new(
        params: ParamsKZG<Bn256>,
        vk: VerifyingKey<G1Affine>,
        deployment_code: Vec<u8>,
    ) -> Self {
        let inner = common::Verifier::new(params, vk);

        Self {
            inner,
            deployment_code,
        }
    }

    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        let vk_path = format!("{assets_dir}/{}", *AGG_VK_FILENAME);
        let deployment_code_path = format!("{assets_dir}/{}", *DEPLOYMENT_CODE_FILENAME);
        if !(Path::new(&vk_path).exists() && Path::new(&deployment_code_path).exists()) {
            panic!("File {vk_path} and {deployment_code_path} must exist");
        }

        let raw_vk = read_all(&vk_path);
        let deployment_code = read_all(&deployment_code_path);

        env::set_var("COMPRESSION_CONFIG", &*LAYER4_CONFIG_PATH);
        let inner = common::Verifier::from_params_dir(params_dir, *LAYER4_DEGREE, &raw_vk);

        Self {
            inner,
            deployment_code,
        }
    }

    pub fn verify_agg_evm_proof(&self, batch_proof: BatchProof) -> bool {
        verify_evm_calldata(self.deployment_code.clone(), batch_proof.calldata())
    }
}
