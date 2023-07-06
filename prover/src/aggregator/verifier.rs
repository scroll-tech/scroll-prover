use crate::{utils::load_params, Proof};
use aggregator::CompressionCircuit;
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier_sdk::{evm_verify, gen_evm_verifier, verify_snark_shplonk, CircuitExt};
use std::{io::Cursor, path::Path};

#[derive(Debug)]
pub struct Verifier {
    params: ParamsKZG<Bn256>,
    vk: Option<VerifyingKey<G1Affine>>,
}

impl Verifier {
    pub fn new(params: ParamsKZG<Bn256>, vk: Option<VerifyingKey<G1Affine>>) -> Self {
        Self { params, vk }
    }

    pub fn from_params(params: ParamsKZG<Bn256>, raw_vk: Option<Vec<u8>>) -> Self {
        let vk = raw_vk.as_ref().map(|k| {
            VerifyingKey::<G1Affine>::read::<_, CompressionCircuit>(
                &mut Cursor::new(&k),
                SerdeFormat::Processed,
            )
            .unwrap()
        });

        Self { params, vk }
    }

    pub fn from_params_dir(params_dir: &str, degree: u32, vk: Option<Vec<u8>>) -> Self {
        let params = load_params(params_dir, degree, None).unwrap();

        Self::from_params(params, vk)
    }

    pub fn verify_agg_proof(&self, proof: Proof) -> Result<bool> {
        let vk = match &self.vk {
            Some(vk) => vk,
            None => panic!("Aggregation verification key is missing"),
        };

        Ok(verify_snark_shplonk::<CompressionCircuit>(
            &self.params,
            proof.to_snark(),
            vk,
        ))
    }

    // Should panic if failed to verify.
    pub fn evm_verify<C: CircuitExt<Fr>>(&self, proof: &Proof, yul_file_path: Option<&Path>) {
        let vk = match &self.vk {
            Some(vk) => vk,
            None => panic!("Aggregation verification key is missing"),
        };

        let num_instance = proof.num_instance().expect("Not a EVM proof").clone();

        let deployment_code = gen_evm_verifier::<C, Kzg<Bn256, Bdfg21>>(
            &self.params,
            vk,
            num_instance,
            yul_file_path,
        );

        evm_verify(deployment_code, proof.instances(), proof.proof().to_vec());
    }
}
