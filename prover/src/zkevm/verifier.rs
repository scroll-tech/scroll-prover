use super::circuit::TargetCircuit;
use crate::{config::INNER_DEGREE, utils::load_params, Proof};
use anyhow::{bail, Result};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{keygen_vk, verify_proof, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{commitment::ParamsKZG, multiopen::VerifierSHPLONK, strategy::AccumulatorStrategy},
        VerificationStrategy,
    },
    transcript::TranscriptReadBuffer,
    SerdeFormat,
};
use itertools::Itertools;
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier_sdk::{verify_snark_shplonk, AggregationCircuit, Snark};
use std::{collections::HashMap, io::Cursor};

const CHUNK_DEGREE: u32 = 25;

pub struct Verifier {
    inner_params: ParamsKZG<Bn256>,
    chunk_params: ParamsKZG<Bn256>,
    chunk_vk: Option<VerifyingKey<G1Affine>>,
    inner_vks: HashMap<String, VerifyingKey<G1Affine>>,
}

impl Verifier {
    pub fn from_params(
        inner_params: ParamsKZG<Bn256>,
        chunk_params: ParamsKZG<Bn256>,
        raw_chunk_vk: Option<Vec<u8>>,
    ) -> Self {
        let chunk_vk = raw_chunk_vk.as_ref().map(|k| {
            VerifyingKey::<G1Affine>::read::<_, AggregationCircuit>(
                &mut Cursor::new(&k),
                SerdeFormat::Processed,
            )
            .unwrap()
        });

        Self {
            inner_params,
            chunk_params,
            chunk_vk,
            inner_vks: Default::default(),
        }
    }

    pub fn from_params_dir(params_dir: &str, chunk_vk: Option<Vec<u8>>) -> Self {
        let chunk_params = load_params(params_dir, CHUNK_DEGREE, None).unwrap();
        let inner_params = load_params(params_dir, *INNER_DEGREE, None).unwrap_or_else(|_| {
            assert!(CHUNK_DEGREE >= *INNER_DEGREE);
            log::warn!(
                "Optimization: download params{} to params dir",
                *INNER_DEGREE
            );

            let mut new_params = chunk_params.clone();
            new_params.downsize(*INNER_DEGREE);
            new_params
        });

        Self::from_params(inner_params, chunk_params, chunk_vk)
    }

    pub fn verify_chunk_proof(&self, proof: Proof) -> Result<bool> {
        let chunk_vk = match &self.chunk_vk {
            Some(vk) => vk,
            None => panic!("Chunk verification key is missing"),
        };

        Ok(verify_snark_shplonk::<AggregationCircuit>(
            &self.chunk_params,
            proof.to_snark(),
            chunk_vk,
        ))
    }

    pub fn verify_chunk_evm_proof(&self, proof: Proof) -> Result<bool> {
        let chunk_vk = match &self.chunk_vk {
            Some(vk) => vk,
            None => panic!("Chunk verification key is missing"),
        };

        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.proof());

        // Deserialize instances
        let instances = proof.instances();
        let instances = instances.iter().map(|ins| ins.as_slice()).collect_vec();

        Ok(VerificationStrategy::<_, VerifierSHPLONK<Bn256>>::finalize(
            verify_proof::<_, VerifierSHPLONK<Bn256>, _, EvmTranscript<_, _, _, _>, _>(
                &self.chunk_params,
                chunk_vk,
                AccumulatorStrategy::new(&self.inner_params),
                &[instances.as_slice()],
                &mut transcript,
            )?,
        ))
    }

    pub fn verify_inner_proof<C: TargetCircuit>(&mut self, snark: &Snark) -> Result<()> {
        let verifier_params = self.inner_params.verifier_params();
        let vk = self.inner_vks.entry(C::name()).or_insert_with(|| {
            let circuit = C::dummy_inner_circuit();
            keygen_vk(&self.inner_params, &circuit)
                .unwrap_or_else(|_| panic!("Failed to generate {} vk", C::name()))
        });
        if verify_snark_shplonk::<C::Inner>(verifier_params, snark.clone(), vk) {
            Ok(())
        } else {
            bail!("Snark verification failed".to_string())
        }
    }
}
