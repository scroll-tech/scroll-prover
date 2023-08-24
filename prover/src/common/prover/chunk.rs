use super::Prover;
use crate::{
    config::{asset_file_path, LayerId, LAYER1_DEGREE, LAYER2_DEGREE},
    utils::{chunk_trace_to_witness_block, gen_rng, get_block_trace_from_file, read_env_var},
};
use aggregator::extract_proof_and_instances_with_pairing_check;
use anyhow::{anyhow, Result};
use halo2_proofs::halo2curves::bn256::Fr;
use once_cell::sync::Lazy;
use snark_verifier_sdk::Snark;
use std::path::Path;
use zkevm_circuits::evm_circuit::witness::Block;

static SIMPLE_TRACE_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("SIMPLE_TRACE_FILENAME", "simple_trace.json".to_string()));

impl Prover {
    pub fn gen_chunk_pk(&mut self, output_dir: Option<&str>) -> Result<()> {
        if self.pk(LayerId::Layer2.id()).is_some() {
            return Ok(());
        }

        let simple_trace_path = asset_file_path(&SIMPLE_TRACE_FILENAME);
        if !Path::new(&simple_trace_path).exists() {
            panic!("File {simple_trace_path} must exist");
        }
        let simple_trace = get_block_trace_from_file(simple_trace_path);
        let witness_block = chunk_trace_to_witness_block(vec![simple_trace])?;
        let layer1_snark =
            self.load_or_gen_last_chunk_snark("empty", &witness_block, output_dir)?;

        self.gen_comp_pk(LayerId::Layer2, layer1_snark)
    }

    pub fn load_or_gen_final_chunk_snark(
        &mut self,
        name: &str,
        witness_block: &Block<Fr>,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        let layer1_snark = self.load_or_gen_last_chunk_snark(name, witness_block, output_dir)?;

        // Load or generate compression thin snark (layer-2).
        let layer2_snark = self.load_or_gen_comp_snark(
            name,
            "layer2",
            true,
            *LAYER2_DEGREE,
            layer1_snark,
            output_dir,
        )?;
        log::info!("Got compression thin snark (layer-2): {name}");

        Ok(layer2_snark)
    }

    // Generate previous snark before the final one.
    // Then it could be used to generate a normal or EVM proof for verification.
    pub fn load_or_gen_last_chunk_snark(
        &mut self,
        name: &str,
        witness_block: &Block<Fr>,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        // Load or generate inner snark.
        let inner_snark = self.load_or_gen_inner_snark(name, "inner", witness_block, output_dir)?;
        log::info!("Got inner snark: {name}");

        // Check pairing for super circuit.
        extract_proof_and_instances_with_pairing_check(
            self.params(*LAYER1_DEGREE),
            &[inner_snark.clone()],
            gen_rng(),
        )
        .map_err(|err| anyhow!("Failed to check pairing for super circuit: {err:?}"))?;

        // Load or generate compression wide snark (layer-1).
        let layer1_snark = self.load_or_gen_comp_snark(
            name,
            "layer1",
            false,
            *LAYER1_DEGREE,
            inner_snark,
            output_dir,
        )?;
        log::info!("Got compression wide snark (layer-1): {name}");

        Ok(layer1_snark)
    }
}
