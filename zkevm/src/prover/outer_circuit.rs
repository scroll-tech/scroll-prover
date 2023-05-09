//! This module implements outer circuit related APIs for Prover.

use super::{AggCircuitProof, Prover};
use crate::circuit::SuperCircuit;
use crate::io::{serialize_fr_tensor, serialize_vk};
use crate::prover::TargetCircuitProof;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use snark_verifier_sdk::evm::gen_evm_proof_shplonk;
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::{gen_pk, CircuitExt};
use types::eth::BlockTrace;

impl Prover {
    /// Input a block trace, generate a proof for the aggregation circuit.
    /// This proof is verifiable by the evm.
    pub fn create_agg_circuit_proof(
        &mut self,
        block_trace: &BlockTrace,
    ) -> anyhow::Result<AggCircuitProof> {
        self.create_agg_circuit_proof_batch(&[block_trace.clone()])
    }

    /// Input a list of block traces, generate a proof for the aggregation circuit.
    /// This proof is verifiable by the evm.
    pub fn create_agg_circuit_proof_batch(
        &mut self,
        block_traces: &[BlockTrace],
    ) -> anyhow::Result<AggCircuitProof> {
        let circuit_results: Vec<TargetCircuitProof> =
            vec![self.prove_inner_circuit::<SuperCircuit>(block_traces)?];
        self.create_agg_proof_by_inner_proofs(circuit_results.as_ref())
    }

    /// Input the inner circuit proofs, output the aggregation proof.
    pub fn create_agg_proof_by_inner_proofs(
        &mut self,
        inner_circuit_results: &[TargetCircuitProof],
    ) -> anyhow::Result<AggCircuitProof> {
        // build the aggregation circuit inputs from the inner circuit outputs
        let agg_circuit = AggregationCircuit::new(
            &self.agg_params,
            inner_circuit_results.iter().map(|p| p.snark.clone()),
            XorShiftRng::from_seed([0u8; 16]),
        );

        // total number of blocks proved
        let total_proved_block_count = inner_circuit_results
            .iter()
            .map(|x| x.num_of_proved_blocks)
            .sum();
        let total_block_count: usize = inner_circuit_results
            .iter()
            .map(|x| x.total_num_of_blocks)
            .sum();

        log::info!(
            "create agg proof done, block proved {}/{}",
            total_proved_block_count,
            total_block_count
        );

        self.create_agg_proof_by_agg_circuit(&agg_circuit, total_proved_block_count)
    }

    /// Input an aggregation circuit, output the aggregation proof.
    ///
    /// The actual work for the outer circuit prover.
    ///
    pub fn create_agg_proof_by_agg_circuit(
        &mut self,
        agg_circuit: &AggregationCircuit,
        total_proved_block_count: usize,
    ) -> anyhow::Result<AggCircuitProof> {
        let seed = [0u8; 16];
        let mut rng = XorShiftRng::from_seed(seed);
        let agg_pk = gen_pk(&self.agg_params, agg_circuit, None);

        let agg_proof = gen_evm_proof_shplonk(
            &self.agg_params,
            &agg_pk,
            agg_circuit.clone(),
            agg_circuit.instances(),
            &mut rng,
        );

        // Serialize instances.
        let instances_for_serde = serialize_fr_tensor(&[agg_circuit.instances()]);
        let instance_bytes = serde_json::to_vec(&instances_for_serde)?;

        // Serialize vk.
        let vk_bytes = serialize_vk(agg_pk.get_vk());

        // Set the aggregation pk.
        self.agg_pk = Some(agg_pk);

        Ok(AggCircuitProof {
            proof: agg_proof,
            instance: instance_bytes,
            vk: vk_bytes,
            total_proved_block_count,
        })
    }
}
