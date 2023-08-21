use crate::{
    common,
    config::{AGG_DEGREES, LAYER3_DEGREE, LAYER4_DEGREE},
    io::{read_all, serialize_vk},
    utils::read_env_var,
    BatchProof, ChunkProof,
};
use aggregator::{ChunkHash, MAX_AGG_SNARKS};
use anyhow::{bail, Result};
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use snark_verifier_sdk::Snark;
use std::{iter::repeat, path::Path};

static CHUNK_PROTOCOL_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("CHUNK_PROTOCOL_FILENAME", "chunk.protocol".to_string()));

#[derive(Debug)]
pub struct Prover {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub inner: common::Prover,
    pub chunk_protocol: Vec<u8>,
}

impl Prover {
    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        let inner = common::Prover::from_params_dir(params_dir, &AGG_DEGREES);

        let chunk_protocol_path = format!("{assets_dir}/{}", *CHUNK_PROTOCOL_FILENAME);
        if !Path::new(&chunk_protocol_path).exists() {
            panic!("File {chunk_protocol_path} must exist");
        }
        let chunk_protocol = read_all(&chunk_protocol_path);

        Self {
            inner,
            chunk_protocol,
        }
    }

    // Return true if chunk proofs are valid (same protocol), false otherwise.
    pub fn check_chunk_proofs(&self, chunk_proofs: &[ChunkProof]) -> bool {
        chunk_proofs.iter().enumerate().all(|(i, proof)| {
            let result = proof.protocol == self.chunk_protocol;
            if !result {
                log::error!(
                    "Non-match protocol of chunk-proof index-{}: expected = {:x}, actual = {:x}",
                    i,
                    Sha256::digest(&self.chunk_protocol),
                    Sha256::digest(&proof.protocol),
                );
            }

            result
        })
    }

    pub fn get_vk(&self) -> Option<Vec<u8>> {
        // TODO: replace `layer4` string with an enum value.
        self.inner.pk("layer4").map(|pk| serialize_vk(pk.get_vk()))
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

        if !self.check_chunk_proofs(&chunk_proofs) {
            bail!("non-match-chunk-protocol: {name}");
        }

        let mut layer2_snarks: Vec<_> = chunk_proofs.into_iter().map(|p| p.to_snark()).collect();

        if real_chunk_count < MAX_AGG_SNARKS {
            let padding_snark = layer2_snarks.last().unwrap().clone();
            let mut padding_chunk_hash = *chunk_hashes.last().unwrap();
            padding_chunk_hash.is_padding = true;

            // Extend to MAX_AGG_SNARKS for both chunk hashes and layer-2 snarks.
            chunk_hashes.extend(repeat(padding_chunk_hash).take(MAX_AGG_SNARKS - real_chunk_count));
            layer2_snarks.extend(repeat(padding_snark).take(MAX_AGG_SNARKS - real_chunk_count));
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
