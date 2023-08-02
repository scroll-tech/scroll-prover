use crate::{
    common,
    config::{AGG_DEGREES, LAYER3_DEGREE, LAYER4_DEGREE},
    zkevm::circuit::storage_trace_to_padding_witness_block,
    BatchProof, ChunkProof,
};
use aggregator::{ChunkHash, MAX_AGG_SNARKS};
use anyhow::Result;
use snark_verifier_sdk::Snark;
use std::iter::repeat;

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
        common::Prover::from_params_dir(params_dir, &AGG_DEGREES).into()
    }

    // Return the EVM proof for verification.
    pub fn gen_agg_evm_proof(
        &mut self,
        chunk_hashes_proofs: Vec<(ChunkHash, ChunkProof)>,
        name: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<BatchProof> {
        let name = name.map_or_else(
            || {
                chunk_hashes_proofs
                    .last()
                    .unwrap()
                    .0
                    .public_input_hash()
                    .to_low_u64_le()
                    .to_string()
            },
            |name| name.to_string(),
        );

        let layer3_snark =
            self.load_or_gen_last_agg_snark(&name, chunk_hashes_proofs, output_dir)?;

        // Load or generate final compression thin EVM proof (layer-4).
        let evm_proof = self.inner.load_or_gen_comp_evm_proof(
            &name,
            "layer4",
            true,
            *LAYER4_DEGREE,
            layer3_snark,
            output_dir,
        )?;
        log::info!("Got final compression thin EVM proof (layer-4): {name}");

        let batch_proof = BatchProof::from(evm_proof.proof);
        if let Some(output_dir) = output_dir {
            batch_proof.dump(output_dir, "agg")?;
        }

        Ok(batch_proof)
    }

    // Generate previous snark before the final one.
    // Then it could be used to generate a normal or EVM proof for verification.
    pub fn load_or_gen_last_agg_snark(
        &mut self,
        name: &str,
        chunk_hashes_proofs: Vec<(ChunkHash, ChunkProof)>,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        let real_chunk_count = chunk_hashes_proofs.len();
        assert!((1..=MAX_AGG_SNARKS).contains(&real_chunk_count));

        let (mut chunk_hashes, chunk_proofs): (Vec<_>, Vec<_>) =
            chunk_hashes_proofs.into_iter().unzip();

        let (mut layer2_snarks, mut storage_traces): (Vec<_>, Vec<_>) = chunk_proofs
            .into_iter()
            .map(|proof| proof.to_snark_and_storage_trace())
            .unzip();

        if real_chunk_count < MAX_AGG_SNARKS {
            let padding_witness_block =
                storage_trace_to_padding_witness_block(storage_traces.pop().unwrap())?;
            let padding_chunk_hash = ChunkHash::from_witness_block(&padding_witness_block, true);
            log::info!("Got padding witness block and chunk hash");

            let layer2_padding_snark = self.inner.load_or_gen_final_chunk_snark(
                &format!("padding_{name}"),
                &padding_witness_block,
                output_dir,
            )?;
            log::info!("Got padding snark (layer-2): {name}");

            // Extend to MAX_AGG_SNARKS for both chunk hashes and layer-2 snarks.
            chunk_hashes.extend(repeat(padding_chunk_hash).take(MAX_AGG_SNARKS - real_chunk_count));
            layer2_snarks
                .extend(repeat(layer2_padding_snark).take(MAX_AGG_SNARKS - real_chunk_count));
        }

        // Load or generate aggregation snark (layer-3).
        let layer3_snark = self.inner.load_or_gen_agg_snark(
            name,
            "layer3",
            *LAYER3_DEGREE,
            &chunk_hashes,
            &layer2_snarks,
            output_dir,
        )?;
        log::info!("Got aggregation snark (layer-3): {name}");

        Ok(layer3_snark)
    }
}
