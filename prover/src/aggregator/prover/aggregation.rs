use super::Prover;
use crate::{
    io::{load_snark, write_snark},
    utils::gen_rng,
};
use aggregator::{AggregationCircuit, BatchHash, ChunkHash};
use anyhow::{anyhow, Result};
use rand::Rng;
use snark_verifier_sdk::Snark;
use std::env::set_var;

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
        )
        .map_err(|err| anyhow!("Failed to construct aggregation circuit: {err:?}"))?;

        self.gen_snark(id, degree, &mut rng, circuit)
    }

    pub fn load_or_gen_agg_snark(
        &mut self,
        name: &str,
        id: &str,
        degree: u32,
        real_chunk_hashes: &[ChunkHash],
        real_and_padding_snarks: &[Snark],
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        let file_path = format!(
            "{}/aggregation_snark_{}.json",
            output_dir.unwrap_or_default(),
            name
        );

        match output_dir.and_then(|_| load_snark(&file_path).ok().flatten()) {
            Some(snark) => Ok(snark),
            None => {
                set_var("AGGREGATION_CONFIG", format!("./configs/{id}.config"));

                let rng = gen_rng();
                let result =
                    self.gen_agg_snark(id, degree, rng, real_chunk_hashes, real_and_padding_snarks);
                if let (Some(_), Ok(snark)) = (output_dir, &result) {
                    write_snark(&file_path, snark);
                }

                result
            }
        }
    }
}
