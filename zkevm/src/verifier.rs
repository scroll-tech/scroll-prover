use std::collections::HashMap;
use std::io::Cursor;

use crate::circuit::{TargetCircuit, AGG_DEGREE, DEGREE};
use crate::io::load_instances;
use crate::prover::{AggCircuitProof, TargetCircuitProof};
use crate::utils::load_params;
use anyhow::anyhow;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::plonk::{keygen_vk, verify_proof};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_proofs::poly::kzg::strategy::{AccumulatorStrategy};
use halo2_proofs::poly::VerificationStrategy;
use halo2_proofs::transcript::TranscriptReadBuffer;
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier_sdk::evm::evm_verify;
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::halo2::verify_snark_shplonk;

pub struct Verifier {
    params: ParamsKZG<Bn256>,
    agg_params: ParamsKZG<Bn256>,
    // just for legacy testing code...
    raw_agg_vk: Option<Vec<u8>>,
    agg_vk: Option<VerifyingKey<G1Affine>>,
    target_circuit_vks: HashMap<String, VerifyingKey<G1Affine>>,
}

impl Verifier {
    pub fn new(
        params: ParamsKZG<Bn256>,
        agg_params: ParamsKZG<Bn256>,
        raw_agg_vk: Option<Vec<u8>>,
    ) -> Self {
        if raw_agg_vk.is_none() {
            log::error!("Verifier should better have raw_agg_vk to check consistency");
        }
        let agg_vk = raw_agg_vk.as_ref().map(|k| {
            VerifyingKey::<G1Affine>::read::<_, AggregationCircuit>(
                &mut Cursor::new(&k),
                halo2_proofs::SerdeFormat::Processed,
            )
            .unwrap()
        });

        Self {
            params,
            agg_params,
            agg_vk,
            raw_agg_vk,
            target_circuit_vks: Default::default(),
        }
    }

    pub fn from_params(
        params: ParamsKZG<Bn256>,
        agg_params: ParamsKZG<Bn256>,
        agg_vk: Option<Vec<u8>>,
    ) -> Self {
        Self::new(params, agg_params, agg_vk)
    }

    pub fn from_fpath(params_path: &str, agg_vk: Option<Vec<u8>>) -> Self {
        let params = load_params(params_path, *DEGREE).expect("failed to init params");
        let agg_params = load_params(params_path, *AGG_DEGREE).expect("failed to init params");
        Self::from_params(params, agg_params, agg_vk)
    }

    pub fn verify_agg_circuit_proof(&self, proof: AggCircuitProof) -> anyhow::Result<bool> {
        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.proof.as_slice());

        let vk = match self.agg_vk.clone() {
            Some(p) => p,
            None => panic!("aggregation verification key is not found"),
        };

        // deserialize instances
        let verify_circuit_instance: Vec<Vec<Vec<Fr>>> = {
            let instance = proof.instance;
            load_instances(&instance)
        };
        let verify_circuit_instance1: Vec<Vec<&[Fr]>> = verify_circuit_instance
            .iter()
            .map(|x| x.iter().map(|y| &y[..]).collect())
            .collect();
        let verify_circuit_instance2: Vec<&[&[Fr]]> =
            verify_circuit_instance1.iter().map(|x| &x[..]).collect();

        Ok(VerificationStrategy::<_, VerifierSHPLONK<Bn256>>::finalize(
            verify_proof::<_, VerifierSHPLONK<Bn256>, _, EvmTranscript<_, _, _, _>, _>(
                &self.agg_params,
                &vk,
                AccumulatorStrategy::new(&self.params),
                &verify_circuit_instance2,
                &mut transcript,
            )
            .unwrap(),
        ))
    }

    pub fn verify_target_circuit_proof<C: TargetCircuit>(
        &mut self,
        proof: &TargetCircuitProof,
    ) -> anyhow::Result<()> {
        let verifier_params = self.params.verifier_params();
        let vk = self.target_circuit_vks.entry(C::name()).or_insert_with(|| {
            let circuit = C::dummy_inner_circuit();
            keygen_vk(&self.params, &circuit)
                .unwrap_or_else(|_| panic!("failed to generate {} vk", C::name()))
        });
        if verify_snark_shplonk::<C::Inner>(verifier_params, proof.snark.clone(), vk) {
            Ok(())
        } else {
            Err(anyhow!("snark verification failed".to_string()))
        }
    }

    /// Verifies the proof with EVM byte code.
    /// Panics if verification fails.
    pub fn evm_verify(bytecode: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
        evm_verify(bytecode, instances, proof)
    }
}
