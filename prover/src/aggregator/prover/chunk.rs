use super::Prover;
use crate::{
    config::INNER_DEGREE,
    utils::{gen_rng, metric_of_witness_block, read_env_var},
    zkevm::circuit::TargetCircuit,
};
use anyhow::{bail, Result};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use once_cell::sync::Lazy;
use snark_verifier_sdk::{gen_snark_shplonk, Snark};
use zkevm_circuits::evm_circuit::witness::Block;

pub static MOCK_PROVE: Lazy<bool> = Lazy::new(|| read_env_var("MOCK_PROVE", false));

impl Prover {
    pub fn gen_chunk_snark<C: TargetCircuit>(
        &mut self,
        witness_block: &Block<Fr>,
    ) -> Result<Snark> {
        log::info!(
            "Proving the chunk: {:?}",
            metric_of_witness_block(witness_block)
        );

        let (circuit, instance) = C::from_witness_block(witness_block)?;
        log::info!("Create {} proof", C::name());

        if *MOCK_PROVE {
            log::info!("Mock prove {} start", C::name());
            let prover = MockProver::<Fr>::run(*INNER_DEGREE, &circuit, instance)?;
            if let Err(errs) = prover.verify_par() {
                log::error!("err num: {}", errs.len());
                for err in &errs {
                    log::error!("{}", err);
                }
                bail!("{:#?}", errs);
            }
            log::info!("Mock prove {} done", C::name());
        }

        let (params, pk) = self.inner_params_and_pk::<C>(&C::dummy_inner_circuit())?;

        // Generate the SNARK proof for inner circuit.
        let snark_proof = gen_snark_shplonk(params, pk, circuit, &mut gen_rng(), None::<&str>);

        Ok(snark_proof)
    }
}
