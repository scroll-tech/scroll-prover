use crate::{
    common,
    config::{LAYER1_DEGREE, LAYER2_DEGREE, ZKEVM_DEGREES},
    utils::chunk_trace_to_witness_block,
    Proof,
};
use anyhow::Result;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use std::collections::BTreeMap;
use types::eth::BlockTrace;

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
        common::Prover::from_params_dir(params_dir, &ZKEVM_DEGREES).into()
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
        let inner_snark = self
            .inner
            .load_or_gen_inner_snark(&name, witness_block, output_dir)?;
        log::info!("Got inner snark: {name}");

        // Load or generate compression wide snark (layer-1).
        let layer1_snark = self.inner.load_or_gen_comp_snark(
            &name,
            "layer1",
            true,
            *LAYER1_DEGREE,
            inner_snark,
            output_dir,
        )?;
        log::info!("Got compression wide snark (layer-1): {name}");

        // Load or generate compression thin snark (layer-2).
        let layer2_snark = self.inner.load_or_gen_comp_snark(
            &name,
            "layer2",
            false,
            *LAYER2_DEGREE,
            layer1_snark,
            output_dir,
        )?;
        log::info!("Got compression thin snark (layer-2): {name}");

        let pk = self.inner.pk("layer2").unwrap();
        Proof::from_snark(pk, &layer2_snark)
    }
}
