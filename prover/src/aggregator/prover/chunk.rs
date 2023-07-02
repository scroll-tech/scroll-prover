use super::Prover;
use crate::{
    utils::{gen_rng, metric_of_witness_block, read_env_var},
    zkevm::circuit::{block_traces_to_witness_block, check_batch_capacity, TargetCircuit, DEGREE},
};
use anyhow::{bail, Result};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use once_cell::sync::Lazy;
use snark_verifier_sdk::{gen_snark_shplonk, Snark};
use types::eth::BlockTrace;

pub static MOCK_PROVE: Lazy<bool> = Lazy::new(|| read_env_var("MOCK_PROVE", false));

impl Prover {
    pub fn gen_chunk_snark<C: TargetCircuit>(
        &mut self,
        mut chunk_trace: Vec<BlockTrace>,
    ) -> Result<Snark> {
        if chunk_trace.is_empty() {
            bail!("Empty chunk trace");
        }

        // Will return early if the check finds out the trace exceeds the
        // circuit capacity.
        check_batch_capacity(&mut chunk_trace)?;

        let witness_block = block_traces_to_witness_block(&chunk_trace)?;
        log::info!(
            "Proving the chunk: {:?}",
            metric_of_witness_block(&witness_block)
        );

        let (circuit, instance) = C::from_witness_block(&witness_block)?;

        // Generate the proof for the inner circuit.
        log::info!(
            "Create {} proof of block {} ... block {}, batch len {}",
            C::name(),
            chunk_trace.first().unwrap().header.hash.unwrap(),
            chunk_trace.last().unwrap().header.hash.unwrap(),
            chunk_trace.len()
        );

        if *MOCK_PROVE {
            log::info!("Mock prove {} start", C::name());
            let prover = MockProver::<Fr>::run(*DEGREE, &circuit, instance)?;
            if let Err(errs) = prover.verify_par() {
                log::error!("err num: {}", errs.len());
                for err in &errs {
                    log::error!("{}", err);
                }
                bail!("{:#?}", errs);
            }
            log::info!("Mock prove {} done", C::name());
        }

        // Reuse pk.
        let id = C::name();
        if !self.pks.contains_key(&id) {
            self.gen_inner_pk::<C>(&circuit)?;
        }
        let pk = &self.pks[&id];

        // Generate the SNARK proof for inner circuit.
        let snark_proof =
            gen_snark_shplonk(&self.params, pk, circuit, &mut gen_rng(), None::<String>);

        Ok(snark_proof)
    }
}
