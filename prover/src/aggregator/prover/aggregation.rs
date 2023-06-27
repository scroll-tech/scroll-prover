use super::Prover;
use aggregator::AggregationCircuit;
use anyhow::Result;
use snark_verifier_sdk::Snark;

impl Prover {
    pub fn gen_agg_proof(&self, _snarks: Vec<Snark>) -> Result<(AggregationCircuit, Snark)> {
        todo!()
    }
}
