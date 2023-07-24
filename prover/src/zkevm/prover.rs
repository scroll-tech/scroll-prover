use crate::{
    common,
    config::ZKEVM_DEGREES,
    io::{serialize_vk, write_file},
    utils::chunk_trace_to_witness_block,
};
use anyhow::Result;
use snark_verifier_sdk::Snark;
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
        common::Prover::from_params_dir(params_dir, &ZKEVM_DEGREES).into()
    }

    pub fn gen_chunk_snark(
        &mut self,
        chunk_trace: Vec<BlockTrace>,
        name: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        assert!(!chunk_trace.is_empty());

        let witness_block = chunk_trace_to_witness_block(chunk_trace)?;
        log::info!("Got witness block");

        let name = name.map_or_else(
            || {
                witness_block
                    .context
                    .first_or_default()
                    .number
                    .low_u64()
                    .to_string()
            },
            |name| name.to_string(),
        );

        let snark = self
            .inner
            .load_or_gen_final_chunk_snark(&name, witness_block, output_dir)?;

        if let Some(output_dir) = output_dir {
            let raw_vk = self
                .inner
                .pk("layer2")
                .map_or_else(Vec::new, |pk| serialize_vk(pk.get_vk()));

            write_file(
                &mut output_dir.into(),
                &format!("chunk_{name}.vkey"),
                &raw_vk,
            );
        }

        Ok(snark)
    }
}
