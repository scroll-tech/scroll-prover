use crate::{
    config::AGG_DEGREE,
    utils::{chunk_trace_to_witness_block, gen_rng, load_params},
    zkevm::circuit::SuperCircuit,
    Proof,
};
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use std::{
    collections::{BTreeMap, HashMap},
    env::set_var,
};
use types::eth::BlockTrace;

mod aggregation;
mod chunk;
mod common;
mod compression;

#[derive(Debug)]
pub struct Prover {
    // degree -> params (use BTreeMap to find proper degree for params downsize)
    params_map: BTreeMap<u32, ParamsKZG<Bn256>>,
    // Cached id -> pk
    pk_map: HashMap<String, ProvingKey<G1Affine>>,
}

impl Prover {
    pub fn from_params(params_map: BTreeMap<u32, ParamsKZG<Bn256>>) -> Self {
        Self {
            params_map,
            pk_map: HashMap::new(),
        }
    }

    pub fn from_params_dir(params_dir: &str, degrees: &[u32]) -> Self {
        let params_map = degrees
            .iter()
            .map(|d| (*d, load_params(params_dir, *d, None).unwrap()))
            .collect();

        Self {
            params_map,
            pk_map: HashMap::new(),
        }
    }

    pub fn gen_agg_proof(&mut self, chunk_traces: Vec<Vec<BlockTrace>>) -> Result<Proof> {
        // Convert chunk traces to witness blocks.
        let witness_blocks = chunk_traces
            .into_iter()
            .map(chunk_trace_to_witness_block)
            .collect::<Result<Vec<_>>>()?;

        // Convert witness blocks to chunk hashes.
        let chunk_hashes: Vec<_> = witness_blocks.iter().map(Into::into).collect();

        // Generate chunk snarks.
        let chunk_snarks = witness_blocks
            .into_iter()
            .map(|block| self.gen_chunk_snark::<SuperCircuit>(&block))
            .collect::<Result<Vec<_>>>()?;

        // Generate compression wide snarks (layer-1).
        set_var("VERIFY_CONFIG", "./configs/comp_wide.config");
        let layer1_snarks: Vec<_> = chunk_snarks
            .into_iter()
            .map(|snark| {
                let rng = gen_rng();
                self.gen_comp_snark("comp_wide", true, *AGG_DEGREE, rng, snark)
            })
            .collect();

        // Generate compression thin snarks (layer-2).
        set_var("VERIFY_CONFIG", "./configs/comp_thin.config");
        let layer2_snarks: Vec<_> = layer1_snarks
            .into_iter()
            .map(|snark| {
                let rng = gen_rng();
                self.gen_comp_snark("comp_thin", false, *AGG_DEGREE, rng, snark)
            })
            .collect();

        // Generate aggregation snark (layer-3).
        set_var("VERIFY_CONFIG", "./configs/agg.config");
        let rng = gen_rng();
        let layer3_snark =
            self.gen_agg_snark("agg", *AGG_DEGREE, rng, &chunk_hashes, &layer2_snarks);

        // Generate final compression snarks (layer-4).
        set_var("VERIFY_CONFIG", "./configs/comp_thin.config");
        let rng = gen_rng();
        let layer4_snark = self.gen_comp_snark("comp_thin", false, *AGG_DEGREE, rng, layer3_snark);

        Proof::from_snark(&self.pk_map["comp_thin"], &layer4_snark)
    }
}
