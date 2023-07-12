use super::Prover;
use crate::{config::INNER_DEGREE, utils::gen_rng};
use aggregator::{ChunkHash, DummyChunkHashCircuit};
use anyhow::Result;
use snark_verifier_sdk::{gen_snark_shplonk, Snark};

impl Prover {
    pub fn gen_padding_chunk_snark(&mut self, last_real_chunk_hash: &ChunkHash) -> Result<Snark> {
        let chunk_hash = ChunkHash::dummy_chunk_hash(last_real_chunk_hash);
        let circuit = DummyChunkHashCircuit::new(chunk_hash);

        let (params, pk) = self.params_and_pk("padding_chunk", &circuit, *INNER_DEGREE)?;
        let snark = gen_snark_shplonk(params, pk, circuit, &mut gen_rng(), None::<String>);

        Ok(snark)
    }
}
