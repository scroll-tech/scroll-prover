use crate::{
    common,
    config::{LAYER1_DEGREE, LAYER2_DEGREE, ZKEVM_DEGREES},
    io::serialize_vk,
    utils::chunk_trace_to_witness_block,
    Proof,
};
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier_sdk::Snark;
use std::collections::BTreeMap;
use types::eth::BlockTrace;
use zkevm_circuits::evm_circuit::witness::Block;

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

        let layer1_snark = self.load_or_gen_last_snark(&name, witness_block, output_dir)?;

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

        let raw_vk = self
            .inner
            .pk("layer2")
            .map_or_else(Vec::new, |pk| serialize_vk(pk.get_vk()));
        Proof::from_snark(&layer2_snark, raw_vk)
    }

    // Generate the previous snark before final proof.
    // Then it could be used to generate a normal or EVM proof for verification.
    pub fn load_or_gen_last_snark(
        &mut self,
        name: &str,
        witness_block: Block<Fr>,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        // Load or generate inner snark.
        let inner_snark =
            self.inner
                .load_or_gen_inner_snark(name, "inner", witness_block, output_dir)?;
        log::info!("Got inner snark: {name}");

        // Load or generate compression wide snark (layer-1).
        let layer1_snark = self.inner.load_or_gen_comp_snark(
            name,
            "layer1",
            true,
            *LAYER1_DEGREE,
            inner_snark,
            output_dir,
        )?;
        log::info!("Got compression wide snark (layer-1): {name}");

        Ok(layer1_snark)
    }
}
