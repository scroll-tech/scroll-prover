use super::Prover;
use crate::{
    config::INNER_DEGREE,
    utils::metric_of_witness_block,
    zkevm::circuit::{block_traces_to_witness_block, check_batch_capacity, TargetCircuit},
};
use anyhow::bail;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use types::eth::BlockTrace;

impl<C: TargetCircuit> Prover<C> {
    pub fn mock_prove_target_circuit(block_trace: &BlockTrace) -> anyhow::Result<()> {
        Self::mock_prove_target_circuit_batch(&[block_trace.clone()])
    }

    pub fn mock_prove_target_circuit_batch(block_traces: &[BlockTrace]) -> anyhow::Result<()> {
        log::info!(
            "start mock prove {}, rows needed {:?}",
            C::name(),
            C::estimate_rows(block_traces)
        );
        let original_block_len = block_traces.len();
        let mut block_traces = block_traces.to_vec();
        check_batch_capacity(&mut block_traces)?;
        let witness_block = block_traces_to_witness_block(&block_traces, false)?;
        log::info!(
            "mock proving batch of len {}, batch metric {:?}",
            original_block_len,
            metric_of_witness_block(&witness_block)
        );
        let (circuit, instance) = C::from_witness_block(&witness_block)?;
        let prover = MockProver::<Fr>::run(*INNER_DEGREE, &circuit, instance)?;
        if let Err(errs) = prover.verify_par() {
            log::error!("err num: {}", errs.len());
            for err in &errs {
                log::error!("{}", err);
            }
            bail!("{:#?}", errs);
        }
        log::info!(
            "mock prove {} done. block proved {}/{}, batch metric: {:?}",
            C::name(),
            block_traces.len(),
            original_block_len,
            metric_of_witness_block(&witness_block),
        );
        Ok(())
    }
}
