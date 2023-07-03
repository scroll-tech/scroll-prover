use super::circuit::{
    block_traces_to_witness_block, check_batch_capacity, SuperCircuit, TargetCircuit,
};
use crate::{
    config::INNER_DEGREE,
    proof::Proof,
    utils::{metric_of_witness_block, read_env_var},
};
use anyhow::bail;
use log::info;
use once_cell::sync::Lazy;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::collections::HashMap;
use types::eth::BlockTrace;

use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk2, ProvingKey},
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier_sdk::{
    gen_evm_proof_shplonk, gen_pk, gen_snark_shplonk, AggregationCircuit, CircuitExt, Snark,
};

mod evm;
mod mock;
mod util;

#[cfg(target_os = "linux")]
extern crate procfs;

#[allow(dead_code)]
pub static OPT_MEM: Lazy<bool> = Lazy::new(|| read_env_var("OPT_MEM", false));
pub static MOCK_PROVE: Lazy<bool> = Lazy::new(|| read_env_var("MOCK_PROVE", false));

#[derive(Debug)]
// This is the aggregation prover that takes in a list of traces, produces
// a proof that can be verified on chain.
pub struct Prover {
    pub zkevm_params: ParamsKZG<Bn256>,
    pub agg_params: ParamsKZG<Bn256>,
    /// We may have a list of public keys for different inner circuits.
    /// Those keys are stored as a hash map, and keyed by a `name` String.
    pub target_circuit_pks: HashMap<String, ProvingKey<G1Affine>>,
    pub agg_pk: Option<ProvingKey<G1Affine>>,
}

impl Prover {
    // Build a new Prover from parameters.
    pub fn new(zkevm_params: ParamsKZG<Bn256>, agg_params: ParamsKZG<Bn256>) -> Self {
        Self {
            zkevm_params,
            agg_params,
            target_circuit_pks: Default::default(),
            agg_pk: None,
        }
    }

    // Generate the chunk proof given the chunk trace using Poseidon hash for challenges.
    // The returned proof is expected to be verified by only rust verifier not solidity verifier.
    pub fn gen_chunk_proof(&mut self, chunk_trace: &[BlockTrace]) -> anyhow::Result<Proof> {
        let inner_snark = self.gen_inner_snark::<SuperCircuit>(chunk_trace)?;
        // Compress the inner snark using the aggregation proof.
        self.gen_agg_proof(vec![inner_snark])
    }

    // Generate the chunk proof given the chunk trace using Keccak hash for challenges.
    // The returned proof can be efficiently verified by solidity verifier.
    pub fn gen_chunk_evm_proof(&mut self, chunk_trace: &[BlockTrace]) -> anyhow::Result<Proof> {
        let inner_snark = self.gen_inner_snark::<SuperCircuit>(chunk_trace)?;
        // Compress the inner snark using the aggregation proof.
        self.gen_agg_evm_proof(vec![inner_snark])
    }

    // Generate the snark of the inner circuit
    pub fn gen_inner_snark<C: TargetCircuit>(
        &mut self,
        chunk_trace: &[BlockTrace],
    ) -> anyhow::Result<Snark> {
        if chunk_trace.is_empty() {
            bail!("Empty chunk trace");
        }

        let mut block_traces = chunk_trace.to_vec();

        let (circuit, instance) = {
            // will return early if the check finds out the trace exceeds the circuit capacity
            check_batch_capacity(&mut block_traces)?;

            let witness_block = block_traces_to_witness_block(&block_traces)?;
            log::info!(
                "proving the chunk: {:?}",
                metric_of_witness_block(&witness_block)
            );

            C::from_witness_block(&witness_block)?
        };

        // generate the proof for the inner circuit
        info!(
            "Create {} proof of block {} ... block {}, batch len {}",
            C::name(),
            chunk_trace.first().unwrap().header.hash.unwrap(),
            chunk_trace.last().unwrap().header.hash.unwrap(),
            chunk_trace.len()
        );

        let seed = [0u8; 16];
        let mut rng = XorShiftRng::from_seed(seed);

        if *MOCK_PROVE {
            log::info!("mock prove {} start", C::name());
            let prover = MockProver::<Fr>::run(*INNER_DEGREE, &circuit, instance)?;
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
            self.gen_inner_pk::<C>(&C::dummy_inner_circuit());
        }
        let pk = &self.target_circuit_pks[&C::name()];

        // Generate the SNARK proof for the inner circuit
        let snark_proof =
            gen_snark_shplonk(&self.zkevm_params, pk, circuit, &mut rng, None::<String>);
        Ok(snark_proof)
    }

    // Generate the aggregation proof given the proofs of inner circuit
    pub fn gen_agg_proof(&mut self, snarks: Vec<Snark>) -> anyhow::Result<Proof> {
        // build the aggregation circuit inputs from the inner circuit outputs
        let seed = [0u8; 16];
        let mut rng = XorShiftRng::from_seed(seed);

        let agg_circuit = AggregationCircuit::new(&self.agg_params, snarks, &mut rng);
        let agg_pk = self
            .agg_pk
            .get_or_insert_with(|| gen_pk(&self.agg_params, &agg_circuit, None));

        let agg_proof = gen_snark_shplonk(
            &self.agg_params,
            agg_pk,
            agg_circuit,
            &mut rng,
            None::<String>,
        );

        Proof::from_snark(agg_pk, &agg_proof)
    }

    // Generate the aggregation evm proof given the proofs of inner circuit
    pub fn gen_agg_evm_proof(&mut self, snarks: Vec<Snark>) -> anyhow::Result<Proof> {
        // build the aggregation circuit inputs from the inner circuit outputs
        let seed = [0u8; 16];
        let mut rng = XorShiftRng::from_seed(seed);

        let agg_circuit = AggregationCircuit::new(&self.agg_params, snarks, &mut rng);
        let agg_pk = self
            .agg_pk
            .get_or_insert_with(|| gen_pk(&self.agg_params, &agg_circuit, None));

        let agg_proof = gen_evm_proof_shplonk(
            &self.agg_params,
            agg_pk,
            agg_circuit.clone(),
            agg_circuit.instances(),
            &mut rng,
        );

        Proof::new(
            agg_proof,
            agg_pk.get_vk(),
            &agg_circuit.instances(),
            Some(agg_circuit.num_instance()),
        )
    }

    // Initiates the public key for a given inner circuit.
    pub(crate) fn gen_inner_pk<C: TargetCircuit>(&mut self, circuit: &<C as TargetCircuit>::Inner) {
        Self::tick(&format!("before init pk of {}", C::name()));
        let pk = keygen_pk2(&self.zkevm_params, circuit)
            .unwrap_or_else(|e| panic!("failed to generate {} pk: {:?}", C::name(), e));
        self.target_circuit_pks.insert(C::name(), pk);
        Self::tick(&format!("after init pk of {}", C::name()));
    }
}
