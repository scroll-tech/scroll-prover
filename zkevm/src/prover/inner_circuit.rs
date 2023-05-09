//! Inner circuit related APIs

use super::{Prover, TargetCircuitProof};
use crate::circuit::{block_traces_to_witness_block, check_batch_capacity, TargetCircuit, DEGREE};
use crate::io::{serialize_instance, serialize_vk};
use crate::prover::MOCK_PROVE;
use crate::utils::metric_of_witness_block;
use anyhow::{bail, Error};
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use log::info;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use snark_verifier_sdk::halo2::gen_snark_shplonk;
use types::eth::BlockTrace;

impl Prover {
    /// Input a list of traces, generate an instance for the outer circuit.
    ///
    pub fn prove_inner_circuit<C: TargetCircuit>(
        &mut self,
        block_traces: &[BlockTrace],
    ) -> anyhow::Result<TargetCircuitProof> {
        self.create_target_circuit_proof_batch::<C>(block_traces)
    }

    /// Input a trace, generate a proof for the outer circuit.
    ///
    pub fn create_target_circuit_proof<C: TargetCircuit>(
        &mut self,
        block_trace: &BlockTrace,
    ) -> anyhow::Result<TargetCircuitProof, Error> {
        self.create_target_circuit_proof_batch::<C>(&[block_trace.clone()])
    }

    /// Create a target circuit proof for a list of block traces
    pub fn create_target_circuit_proof_batch<C: TargetCircuit>(
        &mut self,
        block_traces: &[BlockTrace],
    ) -> anyhow::Result<TargetCircuitProof, Error> {
        let total_num_of_blocks = block_traces.len();

        //
        // Process the traces and prepare the witnesses and inputs to the inner circuits
        //
        let ((circuit, instance), num_of_proved_blocks) = {
            let mut block_traces = block_traces.to_vec();
            check_batch_capacity(&mut block_traces)?;
            let witness_block = block_traces_to_witness_block(&block_traces)?;
            log::info!(
                "proving batch of len {}, batch metric {:?}",
                total_num_of_blocks,
                metric_of_witness_block(&witness_block)
            );
            (
                C::from_witness_block(&witness_block)?,
                witness_block.context.ctxs.len(),
            )
        };

        //
        // generate the proof for the inner circuit
        //
        info!(
            "Create {} proof of block {} ... block {}, batch len {}",
            C::name(),
            block_traces[0].header.hash.unwrap(),
            block_traces[block_traces.len() - 1].header.hash.unwrap(),
            block_traces.len()
        );

        let seed = [0u8; 16];
        let mut rng = XorShiftRng::from_seed(seed);
        self.create_target_circuit_proof_from_circuit::<C>(
            circuit,
            instance,
            &mut rng,
            total_num_of_blocks,
            num_of_proved_blocks,
        )
    }

    ///
    /// generate the proof for the inner circuit
    ///
    pub fn create_target_circuit_proof_from_circuit<C: TargetCircuit>(
        &mut self,
        circuit: C::Inner,
        instance: Vec<Vec<Fr>>,
        rng: &mut (impl Rng + Send),
        total_num_of_blocks: usize,
        num_of_proved_blocks: usize,
    ) -> anyhow::Result<TargetCircuitProof, Error> {
        if *MOCK_PROVE {
            log::info!("mock prove {} start", C::name());
            let prover = MockProver::<Fr>::run(*DEGREE as u32, &circuit, instance.clone())?;
            if let Err(errs) = prover.verify_par() {
                log::error!("err num: {}", errs.len());
                for err in &errs {
                    log::error!("{}", err);
                }
                bail!("{:#?}", errs);
            }
            log::info!("mock prove {} done", C::name());
        }

        if !self.target_circuit_pks.contains_key(&C::name()) {
            self.init_pk::<C>(&C::dummy_inner_circuit());
        }
        let pk = &self.target_circuit_pks[&C::name()];

        // Generate the SNARK proof for the inner circuit
        let snark_proof = gen_snark_shplonk(&self.params, pk, circuit, rng, None::<String>);

        let instance_bytes = serialize_instance(&instance);
        let name = C::name();
        log::debug!(
            "{} circuit: proof {:?}, instance len {}",
            name,
            &snark_proof.proof[0..15],
            instance_bytes.len()
        );
        let target_proof = TargetCircuitProof {
            name,
            snark: snark_proof,
            vk: serialize_vk(pk.get_vk()),
            total_num_of_blocks,
            num_of_proved_blocks,
        };

        Ok(target_proof)
    }
}
