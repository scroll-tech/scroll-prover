use super::Prover;
use aggregator::{AggregationCircuit, BatchHash, ChunkHash};
use anyhow::Result;
use rand::Rng;
use snark_verifier_sdk::Snark;

impl Prover {
    pub fn gen_agg_snark(
        &mut self,
        id: &str,
        degree: u32,
        mut rng: impl Rng + Send,
        real_chunk_hashes: &[ChunkHash],
        real_and_padding_snarks: &[Snark],
    ) -> Result<Snark> {
        let batch_hash = BatchHash::construct(real_chunk_hashes);

        let circuit = AggregationCircuit::new(
            self.params(degree),
            real_and_padding_snarks,
            &mut rng,
            batch_hash,
        );

        self.gen_snark(id, degree, &mut rng, circuit)
    }
}
