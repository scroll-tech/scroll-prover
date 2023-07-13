use crate::{
    config::{LAYER1_DEGREE, LAYER2_DEGREE, LAYER3_DEGREE, LAYER4_DEGREE},
    utils::{chunk_trace_to_witness_block, load_params, param_path_for_degree},
    Proof,
};
use aggregator::{ChunkHash, MAX_AGG_SNARKS};
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    iter::repeat,
};
use types::eth::BlockTrace;

mod aggregation;
mod common;
mod compression;
mod evm;
mod inner;
mod padding;

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

    pub fn gen_agg_proof(
        &mut self,
        chunks: Vec<(ChunkHash, Proof)>,
        output_dir: Option<&str>,
    ) -> Result<Proof> {
        let real_chunk_count = chunks.len();
        assert!((1..=MAX_AGG_SNARKS).contains(&real_chunk_count));

        let last_real_chunk_hash = chunks.last().unwrap().0;
        let name = last_real_chunk_hash
            .public_input_hash()
            .to_low_u64_le()
            .to_string();

        // Load or generate padding snark (layer-1).
        let layer1_padding_snark =
            self.load_or_gen_padding_snark(&name, &last_real_chunk_hash, output_dir)?;
        log::info!("Got padding snark (layer-1): {name}");

        // Load or generate compression thin snark for padding (layer-2).
        let layer2_padding_snark = self.load_or_gen_comp_snark(
            &name,
            "layer2",
            false,
            *LAYER2_DEGREE,
            layer1_padding_snark,
            output_dir,
        )?;
        log::info!("Got compression thin snark for padding (layer-2): {name}");

        let (chunk_hashes, mut layer2_snarks): (Vec<_>, Vec<_>) = chunks
            .into_iter()
            .map(|chunk| (chunk.0, chunk.1.to_snark()))
            .unzip();

        // Extend to MAX_AGG_SNARKS by copying the padding snark.
        layer2_snarks.extend(repeat(layer2_padding_snark).take(MAX_AGG_SNARKS - real_chunk_count));

        // Load or generate aggregation snark (layer-3).
        let layer3_snark = self.load_or_gen_agg_snark(
            &name,
            "layer3",
            *LAYER3_DEGREE,
            &chunk_hashes,
            &layer2_snarks,
            output_dir,
        )?;
        log::info!("Got aggregation snark (layer-3): {name}");

        // Load or generate final compression thin snark (layer-4).
        let layer4_snark = self.load_or_gen_comp_snark(
            &name,
            "layer4",
            false,
            *LAYER4_DEGREE,
            layer3_snark,
            output_dir,
        )?;
        log::info!("Got final compression thin snark (layer-4): {name}");

        let pk = self.pk("layer4").unwrap();
        Proof::from_snark(pk, &layer4_snark)
    }

    pub fn gen_chunk_proof(
        &mut self,
        chunk_trace: Vec<BlockTrace>,
        output_dir: Option<&str>,
    ) -> Result<Proof> {
        assert!(!chunk_trace.is_empty());

        let witness_block = chunk_trace_to_witness_block(chunk_trace)?;
        log::info!("Got witness block");

        let name = witness_block
            .context
            .first_or_default()
            .number
            .low_u64()
            .to_string();

        // Load or generate inner snark.
        let inner_snark = self.load_or_gen_inner_snark(&name, witness_block, output_dir)?;
        log::info!("Got inner snark: {name}");

        // Load or generate compression wide snark (layer-1).
        let layer1_snark = self.load_or_gen_comp_snark(
            &name,
            "layer1",
            true,
            *LAYER1_DEGREE,
            inner_snark,
            output_dir,
        )?;
        log::info!("Got compression wide snark (layer-1): {name}");

        // Load or generate compression thin snark (layer-2).
        let layer2_snark = self.load_or_gen_comp_snark(
            &name,
            "layer2",
            false,
            *LAYER2_DEGREE,
            layer1_snark,
            output_dir,
        )?;
        log::info!("Got compression thin snark (layer-2): {name}");

        let pk = self.pk("layer2").unwrap();
        Proof::from_snark(pk, &layer2_snark)
    }
}
