use super::Prover;
use aggregator::{AggregationCircuit, ChunkHash};
use rand::Rng;
use snark_verifier_sdk::Snark;

impl Prover {
    pub fn gen_agg_snark(
        &mut self,
        id: &str,
        degree: u32,
        mut rng: impl Rng + Send,
        chunk_hashes: &[ChunkHash],
        prev_snarks: &[Snark],
    ) -> Snark {
        let circuit =
            AggregationCircuit::new(self.params(degree), prev_snarks, &mut rng, chunk_hashes);

        self.gen_snark(id, degree, &mut rng, circuit)
    }
}
