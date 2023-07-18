use crate::{
    common,
    config::{AGG_DEGREES, LAYER2_DEGREE, LAYER3_DEGREE, LAYER4_DEGREE},
    Proof,
};
use aggregator::{ChunkHash, MAX_AGG_SNARKS};
use anyhow::Result;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use std::{collections::BTreeMap, iter::repeat};

#[derive(Debug)]
pub struct Prover {
    inner: common::Prover,
}

impl From<common::Prover> for Prover {
    fn from(inner: common::Prover) -> Self {
        Self { inner }
    }
}

impl Prover {
    pub fn from_params(params_map: BTreeMap<u32, ParamsKZG<Bn256>>) -> Self {
        common::Prover::from_params(params_map).into()
    }

    pub fn from_params_dir(params_dir: &str) -> Self {
        common::Prover::from_params_dir(params_dir, &AGG_DEGREES).into()
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
            self.inner
                .load_or_gen_padding_snark(&name, &last_real_chunk_hash, output_dir)?;
        log::info!("Got padding snark (layer-1): {name}");

        // Load or generate compression thin snark for padding (layer-2).
        let layer2_padding_snark = self.inner.load_or_gen_comp_snark(
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
        let layer3_snark = self.inner.load_or_gen_agg_snark(
            &name,
            "layer3",
            *LAYER3_DEGREE,
            &chunk_hashes,
            &layer2_snarks,
            output_dir,
        )?;
        log::info!("Got aggregation snark (layer-3): {name}");

        // Load or generate final compression thin snark (layer-4).
        let layer4_snark = self.inner.load_or_gen_comp_snark(
            &name,
            "layer4",
            false,
            *LAYER4_DEGREE,
            layer3_snark,
            output_dir,
        )?;
        log::info!("Got final compression thin snark (layer-4): {name}");

        let pk = self.inner.pk("layer4").unwrap();
        Proof::from_snark(pk, &layer4_snark)
    }
}
