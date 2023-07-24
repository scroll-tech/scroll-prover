use crate::{
    common,
    config::{AGG_DEGREES, LAYER3_DEGREE, LAYER4_DEGREE},
    io::serialize_vk,
    zkevm::circuit::block_traces_to_padding_witness_block,
    Proof,
};
use aggregator::{ChunkHash, MAX_AGG_SNARKS};
use anyhow::Result;
use snark_verifier_sdk::Snark;
use std::{iter::repeat, path::PathBuf};
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
        common::Prover::from_params_dir(params_dir, &AGG_DEGREES).into()
    }

    pub fn gen_agg_proof(
        &mut self,
        chunk_hashes_snarks: Vec<(ChunkHash, Snark)>,
        last_chunk_trace: &[BlockTrace],
        name: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<Proof> {
        let name = name.map_or_else(
            || {
                chunk_hashes_snarks
                    .last()
                    .unwrap()
                    .0
                    .public_input_hash()
                    .to_low_u64_le()
                    .to_string()
            },
            |name| name.to_string(),
        );

        let layer3_snark = self.load_or_gen_last_agg_snark(
            &name,
            chunk_hashes_snarks,
            last_chunk_trace,
            output_dir,
        )?;

        // Load or generate final compression thin snark (layer-4).
        let layer4_snark = self.inner.load_or_gen_comp_snark(
            &name,
            "layer4",
            true,
            *LAYER4_DEGREE,
            layer3_snark,
            output_dir,
        )?;
        log::info!("Got final compression thin snark (layer-4): {name}");

        let raw_vk = self
            .inner
            .pk("layer4")
            .map_or_else(Vec::new, |pk| serialize_vk(pk.get_vk()));

        let result = Proof::from_snark(&layer4_snark, raw_vk);
        if let (Some(output_dir), Ok(proof)) = (output_dir, &result) {
            proof.dump(&mut PathBuf::from(output_dir), "agg")?;
        }

        result
    }

    // Generate previous snark before the final one.
    // Then it could be used to generate a normal or EVM proof for verification.
    pub fn load_or_gen_last_agg_snark(
        &mut self,
        name: &str,
        chunk_hashes_snarks: Vec<(ChunkHash, Snark)>,
        last_chunk_trace: &[BlockTrace],
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        let real_chunk_count = chunk_hashes_snarks.len();
        assert!((1..=MAX_AGG_SNARKS).contains(&real_chunk_count));

        let (mut chunk_hashes, mut layer2_snarks): (Vec<_>, Vec<_>) =
            chunk_hashes_snarks.into_iter().unzip();

        if real_chunk_count < MAX_AGG_SNARKS {
            let padding_witness_block = block_traces_to_padding_witness_block(last_chunk_trace)?;
            let padding_chunk_hash = ChunkHash::from_witness_block(&padding_witness_block, true);
            log::info!("Got padding witness block and chunk hash");

            let layer2_padding_snark = self.inner.load_or_gen_final_chunk_snark(
                &format!("padding_{name}"),
                padding_witness_block,
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
