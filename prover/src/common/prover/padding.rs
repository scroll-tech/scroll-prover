use super::Prover;
use crate::{
    config::INNER_DEGREE,
    io::{load_snark, write_snark},
    utils::gen_rng,
};
use aggregator::{ChunkHash, DummyChunkHashCircuit};
use anyhow::Result;
use snark_verifier_sdk::{gen_snark_shplonk, Snark};

impl Prover {
    pub fn gen_padding_snark(&mut self, last_real_chunk_hash: &ChunkHash) -> Result<Snark> {
        let chunk_hash = ChunkHash::dummy_chunk_hash(last_real_chunk_hash);
        let circuit = DummyChunkHashCircuit::new(chunk_hash);

        let (params, pk) = self.params_and_pk("padding", &circuit, *INNER_DEGREE)?;
        let snark = gen_snark_shplonk(params, pk, circuit, &mut gen_rng(), None::<String>);

        Ok(snark)
    }

    pub fn load_or_gen_padding_snark(
        &mut self,
        name: &str,
        last_real_chunk_hash: &ChunkHash,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        let file_path = format!(
            "{}/padding_snark_{}.json",
            output_dir.unwrap_or_default(),
            name
        );

        match output_dir.and_then(|_| load_snark(&file_path).ok().flatten()) {
            Some(snark) => Ok(snark),
            None => {
                let result = self.gen_padding_snark(last_real_chunk_hash);
                if let (Some(_), Ok(snark)) = (output_dir, &result) {
                    write_snark(&file_path, snark);
                }

                result
            }
        }
    }
}
