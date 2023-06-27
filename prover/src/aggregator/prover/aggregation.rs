use super::Prover;
use crate::proof::Proof;
use aggregator::AggregationCircuit;
use anyhow::Result;
use snark_verifier_sdk::Snark;

impl Prover {
    pub fn build_agg_circuit(&self, _snarks: Vec<Snark>) -> Result<AggregationCircuit> {
        todo!()
    }

    pub fn gen_agg_proof(&self, _snarks: Vec<Snark>) -> Result<Proof> {
        todo!()
    }
}
