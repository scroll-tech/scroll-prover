use crate::{
    config::{LAYER1_DEGREE, LAYER2_DEGREE},
    utils::{chunk_trace_to_witness_block, load_params, param_path_for_degree},
    Proof,
};
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use types::eth::BlockTrace;

mod aggregation;
mod compression;
mod evm;
mod inner;
mod padding;
mod utils;

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
