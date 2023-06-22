use super::circuit::{block_traces_to_witness_block, check_batch_capacity, TargetCircuit, DEGREE};
use super::proof::Proof;
use super::utils::{metric_of_witness_block, read_env_var};
use crate::circuit::SuperCircuit;
use crate::io::{serialize_fr_tensor, serialize_instance, serialize_vk};

use anyhow::{bail, Error};
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::plonk::{ProvingKey, keygen_pk2};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use log::info;
use once_cell::sync::Lazy;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use snark_verifier_sdk::evm::gen_evm_proof_shplonk;
use snark_verifier_sdk::halo2::{gen_snark_shplonk, aggregation::AggregationCircuit};
use snark_verifier_sdk::{gen_pk, CircuitExt, Snark};
use std::collections::HashMap;
use types::eth::ChunkTrace;

mod evm;
// mod inner_circuit;
// mod inner_proof;
mod mock;
// mod outer_circuit;
// mod outer_proof;
mod util;

// pub use inner_proof::TargetCircuitProof;
// pub use outer_proof::AggCircuitProof;

#[cfg(target_os = "linux")]
extern crate procfs;

pub static OPT_MEM: Lazy<bool> = Lazy::new(|| read_env_var("OPT_MEM", false));
pub static MOCK_PROVE: Lazy<bool> = Lazy::new(|| read_env_var("MOCK_PROVE", false));

#[derive(Debug)]
/// This is the aggregation prover that takes in a list of traces, produces
/// a proof that can be verified on chain.
pub struct Prover {
    pub zkevm_params: ParamsKZG<Bn256>,
    pub agg_params: ParamsKZG<Bn256>,
    /// We may have a list of public keys for different inner circuits.
    /// Those keys are stored as a hash map, and keyed by a `name` String.
    pub target_circuit_pks: HashMap<String, ProvingKey<G1Affine>>,
    pub agg_pk: Option<ProvingKey<G1Affine>>,
}

impl Prover {
     /// Build a new Prover from parameters.
     pub fn new(zkevm_params: ParamsKZG<Bn256>, agg_params: ParamsKZG<Bn256>) -> Self {
        Self {
            zkevm_params,
            agg_params,
            target_circuit_pks: Default::default(),
            agg_pk: None,
        }
    }

    /// Generate the chunk proof given the chunk trace
    pub fn gen_chunk_proof(
        &mut self,
        chunk_trace: &ChunkTrace,
    ) -> anyhow::Result<Proof> {
        let inner_proof = self.gen_inner_proof::<SuperCircuit>(chunk_trace)?;
        // compress the inner proof using the aggregation proof
        let agg_proof = self.gen_agg_proof(vec![inner_proof])?;

        Proof::from_snark(self.agg_pk.as_ref().unwrap(), &agg_proof)
    }

    /// Generate the proof of the inner circuit
    pub fn gen_inner_proof<C: TargetCircuit>(
        &mut self,
        chunk_trace: &ChunkTrace,
    ) -> anyhow::Result<Snark> {
        let mut block_traces = chunk_trace.0.to_vec();

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
            chunk_trace.num_blocks()
        );

        let seed = [0u8; 16];
        let mut rng = XorShiftRng::from_seed(seed);

        // if *MOCK_PROVE {
        //     log::info!("mock prove {} start", C::name());
        //     let prover = MockProver::<Fr>::run(*DEGREE as u32, &circuit, instance.clone())?;
        //     if let Err(errs) = prover.verify_par() {
        //         log::error!("err num: {}", errs.len());
        //         for err in &errs {
        //             log::error!("{}", err);
        //         }
        //         bail!("{:#?}", errs);
        //     }
        //     log::info!("mock prove {} done", C::name());
        // }

        if !self.target_circuit_pks.contains_key(&C::name()) {
            self.gen_inner_pk::<C>(&C::dummy_inner_circuit());
        }
        let pk = &self.target_circuit_pks[&C::name()];

        // Generate the SNARK proof for the inner circuit
        let snark_proof = gen_snark_shplonk(&self.zkevm_params, pk, circuit, &mut rng, None::<String>);
        Ok(snark_proof)
    }

    /// Generate the aggregation proof given the proofs of inner circuit
    fn gen_agg_proof(&mut self, snarks: Vec<Snark>) -> anyhow::Result<Snark> {
        // build the aggregation circuit inputs from the inner circuit outputs
        let seed = [0u8; 16];
        let mut rng = XorShiftRng::from_seed(seed);

        let agg_circuit = AggregationCircuit::new(&self.agg_params, snarks, &mut rng);
        let agg_pk = self.agg_pk.get_or_insert_with(|| {
            gen_pk(&self.agg_params, &agg_circuit, None)
        });

        let agg_proof = gen_snark_shplonk(
            &self.agg_params,
            agg_pk,
            agg_circuit,
            &mut rng,
            None::<String>,
        );

        Ok(agg_proof)
    }

    /// Initiates the public key for a given inner circuit.
    pub(crate) fn gen_inner_pk<C: TargetCircuit>(&mut self, circuit: &<C as TargetCircuit>::Inner) {
        Self::tick(&format!("before init pk of {}", C::name()));
        let pk = keygen_pk2(&self.zkevm_params, circuit)
            .unwrap_or_else(|e| panic!("failed to generate {} pk: {:?}", C::name(), e));
        self.target_circuit_pks.insert(C::name(), pk);
        Self::tick(&format!("after init pk of {}", C::name()));
    }
}
