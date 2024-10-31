use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use prover::{common::Verifier, config, consts, io::force_to_read, CompressionCircuit};
use std::{collections::BTreeMap, env};

type SnarkVerifier<'a> = Verifier<'a, CompressionCircuit>;

// FIXME: why we use common::Verifier instead of ChunkVerifier here?
pub fn new_chunk_verifier<'a>(
    params_map: &'a BTreeMap<u32, ParamsKZG<Bn256>>,
    assets_dir: &str,
) -> SnarkVerifier<'a> {
    let raw_vk = force_to_read(assets_dir, &consts::chunk_vk_filename());
    if raw_vk.is_empty() {
        panic!(
            "empty vk read from {}/{}",
            assets_dir,
            &consts::chunk_vk_filename()
        );
    }
    env::set_var("COMPRESSION_CONFIG", &*config::LAYER2_CONFIG_PATH);
    let params = params_map
        .get(&config::LAYER2_DEGREE)
        .expect("should be loaded");
    SnarkVerifier::from_params(params, &raw_vk)
}

pub fn new_batch_verifier<'a>(
    params_map: &'a BTreeMap<u32, ParamsKZG<Bn256>>,
    assets_dir: &str,
) -> SnarkVerifier<'a> {
    let raw_vk = force_to_read(assets_dir, &consts::batch_vk_filename());
    if raw_vk.is_empty() {
        panic!(
            "empty vk read from {}/{}",
            assets_dir,
            &consts::batch_vk_filename()
        );
    }
    env::set_var("COMPRESSION_CONFIG", &*config::LAYER4_CONFIG_PATH);
    let params = params_map
        .get(&config::LAYER4_DEGREE)
        .expect("should be loaded");
    SnarkVerifier::from_params(params, &raw_vk)
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
        //let res = crate::evm::deploy_and_call(self.0.clone(), call_data);
        let res = prover::deploy_and_call(self.0.clone(), call_data);
        log::debug!("verify_evm_proof result {:?}", res);
        res.is_ok()
    }
}
