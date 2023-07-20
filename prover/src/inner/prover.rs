use crate::{
    common,
    config::INNER_DEGREE,
    utils::{chunk_trace_to_witness_block, gen_rng},
    zkevm::circuit::TargetCircuit,
};
use anyhow::Result;
use snark_verifier_sdk::Snark;
use std::marker::PhantomData;
use types::eth::BlockTrace;

mod mock;

#[derive(Debug)]
pub struct Prover<C: TargetCircuit> {
    inner: common::Prover,
    phantom: PhantomData<C>,
}

impl<C: TargetCircuit> From<common::Prover> for Prover<C> {
    fn from(inner: common::Prover) -> Self {
        Self {
            inner,
            phantom: PhantomData,
        }
    }
}

impl<C: TargetCircuit> Prover<C> {
    pub fn from_params_dir(params_dir: &str) -> Self {
        common::Prover::from_params_dir(params_dir, &[*INNER_DEGREE]).into()
    }

    pub fn gen_inner_snark(&mut self, block_traces: Vec<BlockTrace>) -> Result<Snark> {
        assert!(!block_traces.is_empty());

        let rng = gen_rng();
        let witness_block = chunk_trace_to_witness_block(block_traces)?;

        self.inner.gen_inner_snark::<C>(rng, &witness_block)
    }
}
