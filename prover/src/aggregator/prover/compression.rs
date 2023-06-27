use super::Prover;
use crate::proof::Proof;
use anyhow::Result;
use snark_verifier_sdk::Snark;

impl Prover {
    pub fn gen_comp_proof(&self, _snarks: Vec<Snark>) -> Result<Proof> {
        todo!()
    }
}
