use crate::{
    config::{AGG_LAYER1_DEGREE, AGG_LAYER2_DEGREE, AGG_LAYER3_DEGREE, AGG_LAYER4_DEGREE},
    utils::{chunk_trace_to_witness_block, gen_rng, load_params, param_path_for_degree},
    zkevm::circuit::SuperCircuit,
    Proof,
};
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
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
        let degrees = BTreeSet::from_iter(degrees);
        let max_degree = **degrees.last().unwrap();

        // Downsize params if any params of degree doesn't exist.
        let mut params_map = BTreeMap::new();
        for d in BTreeSet::from_iter(degrees).into_iter().rev() {
            let params = match load_params(params_dir, *d, None) {
                Ok(params) => params,
                Err(_) => {
                    let params: &ParamsKZG<_> = params_map
                        .first_key_value()
                        .unwrap_or_else(|| {
                            panic!(
                                "File `{}` must exist",
                                param_path_for_degree(params_dir, max_degree)
                            )
                        })
                        .1;

                    let mut params: ParamsKZG<_> = params.clone();
                    params.downsize(*d);

                    log::warn!("Optimization: download params{d} to params dir",);

                    params
                }
            };

            params_map.insert(*d, params);
        }

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
        set_var("VERIFY_CONFIG", "./configs/agg_layer1.config");
        let layer1_snarks: Vec<_> = chunk_snarks
            .into_iter()
            .map(|snark| {
                let rng = gen_rng();
                self.gen_comp_snark("agg_layer1", true, *AGG_LAYER1_DEGREE, rng, snark)
            })
            .collect();

        // Generate compression thin snarks (layer-2).
        set_var("VERIFY_CONFIG", "./configs/agg_layer2.config");
        let layer2_snarks: Vec<_> = layer1_snarks
            .into_iter()
            .map(|snark| {
                let rng = gen_rng();
                self.gen_comp_snark("agg_layer2", false, *AGG_LAYER2_DEGREE, rng, snark)
            })
            .collect();

        // Generate aggregation snark (layer-3).
        set_var("VERIFY_CONFIG", "./configs/agg_layer3.config");
        let rng = gen_rng();
        let layer3_snark = self.gen_agg_snark(
            "agg_layer3",
            *AGG_LAYER3_DEGREE,
            rng,
            &chunk_hashes,
            &layer2_snarks,
        );

        // Generate final compression snarks (layer-4).
        set_var("VERIFY_CONFIG", "./configs/agg_layer4.config");
        let rng = gen_rng();
        let layer4_snark =
            self.gen_comp_snark("agg_layer4", false, *AGG_LAYER4_DEGREE, rng, layer3_snark);

        Proof::from_snark(&self.pk_map["agg_layer4"], &layer4_snark)
    }
}
