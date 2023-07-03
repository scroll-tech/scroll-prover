use super::circuit::TargetCircuit;
use crate::{
    config::{CHUNK_DEGREE, INNER_DEGREE},
    proof::Proof,
    utils::{downsize_params, load_params, DEFAULT_SERDE_FORMAT},
};
use anyhow::anyhow;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{keygen_vk, verify_proof, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{commitment::ParamsKZG, multiopen::VerifierSHPLONK, strategy::AccumulatorStrategy},
        VerificationStrategy,
    },
    transcript::TranscriptReadBuffer,
};
use itertools::Itertools;
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier_sdk::{verify_snark_shplonk, AggregationCircuit, Snark};
use std::{collections::HashMap, io::Cursor};

pub struct Verifier {
    zkevm_params: ParamsKZG<Bn256>,
    agg_params: ParamsKZG<Bn256>,
    agg_vk: Option<VerifyingKey<G1Affine>>,
    target_circuit_vks: HashMap<String, VerifyingKey<G1Affine>>,
}

impl Verifier {
    pub fn new(
        zkevm_params: ParamsKZG<Bn256>,
        agg_params: ParamsKZG<Bn256>,
        raw_agg_vk: Option<Vec<u8>>,
    ) -> Self {
        let agg_vk = raw_agg_vk.as_ref().map(|k| {
            VerifyingKey::<G1Affine>::read::<_, AggregationCircuit>(
                &mut Cursor::new(&k),
                halo2_proofs::SerdeFormat::Processed,
            )
            .unwrap()
        });

        Self {
            zkevm_params,
            agg_params,
            agg_vk,
            target_circuit_vks: Default::default(),
        }
    }

    pub fn from_params(agg_params: ParamsKZG<Bn256>, agg_vk: Option<Vec<u8>>) -> Self {
        assert!(agg_params.k() == *CHUNK_DEGREE);
        let mut params = agg_params.clone();
        downsize_params(&mut params, *INNER_DEGREE);

        Self::new(params, agg_params, agg_vk)
    }

    pub fn from_params_dir(params_dir: &str, agg_vk: Option<Vec<u8>>) -> Self {
        let agg_params = load_params(params_dir, *CHUNK_DEGREE, DEFAULT_SERDE_FORMAT)
            .expect("Failed to load params");
        Self::from_params(agg_params, agg_vk)
    }

    pub fn verify_chunk_proof(&self, proof: Proof) -> anyhow::Result<bool> {
        let vk = match self.agg_vk.clone() {
            Some(k) => k,
            None => panic!("aggregation verification key is missing"),
        };

        Ok(verify_snark_shplonk::<AggregationCircuit>(
            &self.agg_params,
            proof.to_snark(),
            &vk,
        ))
    }

    pub fn verify_chunk_evm_proof(&self, proof: Proof) -> anyhow::Result<bool> {
        let vk = match self.agg_vk.clone() {
            Some(k) => k,
            None => panic!("aggregation verification key is missing"),
        };

        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.proof());

        // deserialize instances
        let instances = proof.instances();
        let instances = instances.iter().map(|ins| ins.as_slice()).collect_vec();

        Ok(VerificationStrategy::<_, VerifierSHPLONK<Bn256>>::finalize(
            verify_proof::<_, VerifierSHPLONK<Bn256>, _, EvmTranscript<_, _, _, _>, _>(
                &self.agg_params,
                &vk,
                AccumulatorStrategy::new(&self.zkevm_params),
                &[instances.as_slice()],
                &mut transcript,
            )?,
        ))
    }

    pub fn verify_inner_proof<C: TargetCircuit>(&mut self, snark: &Snark) -> anyhow::Result<()> {
        let verifier_params = self.zkevm_params.verifier_params();
        let vk = self.target_circuit_vks.entry(C::name()).or_insert_with(|| {
            let circuit = C::dummy_inner_circuit();
            keygen_vk(&self.zkevm_params, &circuit)
                .unwrap_or_else(|_| panic!("failed to generate {} vk", C::name()))
        });
        if verify_snark_shplonk::<C::Inner>(verifier_params, snark.clone(), vk) {
            Ok(())
        } else {
            Err(anyhow!("snark verification failed".to_string()))
        }
    }
}
