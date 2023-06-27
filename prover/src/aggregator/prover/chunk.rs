use super::{utils::tick, Prover};
use crate::{
    utils::{metric_of_witness_block, read_env_var},
    zkevm::circuit::{block_traces_to_witness_block, check_batch_capacity, TargetCircuit, DEGREE},
};
use anyhow::{bail, Result};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, plonk::keygen_pk2};
use once_cell::sync::Lazy;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use snark_verifier_sdk::{gen_snark_shplonk, Snark};
use types::eth::BlockTrace;

pub static MOCK_PROVE: Lazy<bool> = Lazy::new(|| read_env_var("MOCK_PROVE", false));

impl Prover {
    pub fn gen_chunk_proof<C: TargetCircuit>(
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

        // generate the proof for the inner circuit
        log::info!(
            "Create {} proof of block {} ... block {}, batch len {}",
            C::name(),
            chunk_trace.first().unwrap().header.hash.unwrap(),
            chunk_trace.last().unwrap().header.hash.unwrap(),
            chunk_trace.len()
        );

        let seed = [0u8; 16];
        let mut rng = XorShiftRng::from_seed(seed);

        if *MOCK_PROVE {
            log::info!("Mock prove {} start", C::name());
            let prover = MockProver::<Fr>::run(*DEGREE as u32, &circuit, instance)?;
            if let Err(errs) = prover.verify_par() {
                log::error!("err num: {}", errs.len());
                for err in &errs {
                    log::error!("{}", err);
                }
                bail!("{:#?}", errs);
            }
            log::info!("Mock prove {} done", C::name());
        }

        if !self.inner_pks.contains_key(&C::name()) {
            self.gen_inner_pk::<C>(&C::dummy_inner_circuit());
        }
        let pk = &self.inner_pks[&C::name()];

        // Generate the SNARK proof for inner circuit.
        let snark_proof =
            gen_snark_shplonk(&self.inner_params, pk, circuit, &mut rng, None::<String>);

        Ok(snark_proof)
    }

    fn gen_inner_pk<C: TargetCircuit>(&mut self, circuit: &<C as TargetCircuit>::Inner) {
        tick(&format!("Before init pk of {}", C::name()));

        let pk = keygen_pk2(&self.inner_params, circuit)
            .unwrap_or_else(|e| panic!("Failed to generate {} pk: {:?}", C::name(), e));
        self.inner_pks.insert(C::name(), pk);

        tick(&format!("After init pk of {}", C::name()));
    }
}
