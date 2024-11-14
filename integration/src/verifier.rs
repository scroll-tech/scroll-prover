use std::path::PathBuf;

use prover::{force_read, DEPLOYMENT_CODE_FILENAME};

#[derive(Debug)]
pub struct EVMVerifier(Vec<u8>);

impl EVMVerifier {
    pub fn new(deployment_code: Vec<u8>) -> Self {
        Self(deployment_code)
    }

    pub fn from_dirs(assets_dir: &str) -> Self {
        let path = PathBuf::from(assets_dir).join(DEPLOYMENT_CODE_FILENAME.clone());
        Self::new(force_read(&path))
    }

    pub fn verify_evm_proof(&self, call_data: Vec<u8>) -> bool {
        let res = prover::deploy_and_call(self.0.clone(), call_data);
        log::debug!("verify_evm_proof result {:?}", res);
        res.is_ok()
    }
}
