use crate::{
    common, config::ZKEVM_DEGREES, utils::chunk_trace_to_witness_block,
    zkevm::circuit::normalize_withdraw_proof, ChunkProof,
};
use anyhow::Result;
use types::eth::BlockTrace;

#[derive(Debug)]
pub struct Prover {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub inner: common::Prover,
}

impl From<common::Prover> for Prover {
    fn from(inner: common::Prover) -> Self {
        Self { inner }
    }
}

impl Prover {
    pub fn from_params_dir(params_dir: &str) -> Self {
        common::Prover::from_params_dir(params_dir, &ZKEVM_DEGREES).into()
    }

    pub fn gen_chunk_proof(
        &mut self,
        chunk_trace: Vec<BlockTrace>,
        name: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<ChunkProof> {
        assert!(!chunk_trace.is_empty());

        let witness_block = chunk_trace_to_witness_block(chunk_trace)?;
        log::info!("Got witness block");

        let name = name.map_or_else(
            || {
                witness_block
                    .context
                    .first_or_default()
                    .number
                    .low_u64()
                    .to_string()
            },
            |name| name.to_string(),
        );

        let snark = self
            .inner
            .load_or_gen_final_chunk_snark(&name, &witness_block, output_dir)?;

        match output_dir.and_then(|output_dir| ChunkProof::from_json_file(output_dir, &name).ok()) {
            Some(proof) => Ok(proof),
            None => {
                let storage_trace =
                    normalize_withdraw_proof(&witness_block.mpt_updates.withdraw_proof);

                let result = ChunkProof::new(snark, storage_trace, self.inner.pk("layer2"));

                if let (Some(output_dir), Ok(proof)) = (output_dir, &result) {
                    proof.dump(output_dir, &name)?;
                }

                result
            }
        }
    }
}
