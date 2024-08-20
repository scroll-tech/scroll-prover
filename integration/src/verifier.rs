use prover::{common::Verifier, config, consts, io::force_to_read, CompressionCircuit};
use snark_verifier_sdk::verify_evm_calldata;
use std::env;

type SnarkVerifier = Verifier<CompressionCircuit>;

pub fn new_chunk_verifier(params_dir: &str, assets_dir: &str) -> SnarkVerifier {
    let raw_vk = force_to_read(assets_dir, &consts::chunk_vk_filename());
    if raw_vk.is_empty() {
        panic!(
            "empty vk read from {}/{}",
            assets_dir,
            &consts::chunk_vk_filename()
        );
    }
    env::set_var("COMPRESSION_CONFIG", &*config::LAYER2_CONFIG_PATH);
    SnarkVerifier::from_params_dir(params_dir, *config::LAYER2_DEGREE, &raw_vk)
}

pub fn new_batch_verifier(params_dir: &str, assets_dir: &str) -> SnarkVerifier {
    let raw_vk = force_to_read(assets_dir, &consts::batch_vk_filename());
    if raw_vk.is_empty() {
        panic!(
            "empty vk read from {}/{}",
            assets_dir,
            &consts::batch_vk_filename()
        );
    }
    env::set_var("COMPRESSION_CONFIG", &*config::LAYER4_CONFIG_PATH);
    SnarkVerifier::from_params_dir(params_dir, *config::LAYER4_DEGREE, &raw_vk)
}

#[derive(Debug)]
pub struct EVMVerifier(Vec<u8>);

impl EVMVerifier {
    pub fn new(deployment_code: Vec<u8>) -> Self {
        Self(deployment_code)
    }

    pub fn from_dirs(assets_dir: &str) -> Self {
        Self::new(force_to_read(assets_dir, &consts::DEPLOYMENT_CODE_FILENAME))
    }

    pub fn verify_evm_proof(&self, call_data: Vec<u8>) -> bool {
        verify_evm_calldata(self.0.clone(), call_data)
    }
}
