use crate::{io::write_file, utils::load_params, Proof};
use aggregator::CompressionCircuit;
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};
use itertools::Itertools;
use snark_verifier::{
    pcs::kzg::{Bdfg21, Kzg},
    util::arithmetic::PrimeField,
};
use snark_verifier_sdk::{evm_verify, gen_evm_verifier, verify_snark_shplonk, CircuitExt};
use std::{io::Cursor, path::PathBuf, str::FromStr};

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
    pub fn evm_verify<C: CircuitExt<Fr>>(&self, proof: &Proof, output_dir: &str) {
        let vk = match &self.vk {
            Some(vk) => vk,
            None => panic!("Aggregation verification key is missing"),
        };

        let num_instance = proof.num_instance().expect("Not a EVM proof").clone();

        let mut yul_file_path = PathBuf::from_str(&output_dir).unwrap();
        yul_file_path.push("evm_verifier.yul");

        // Generate deployment code and dump YUL file.
        let deployment_code = gen_evm_verifier::<C, Kzg<Bn256, Bdfg21>>(
            &self.params,
            vk,
            num_instance,
            Some(yul_file_path.as_path()),
        );

        // Dump bytecode.
        let mut output_dir = PathBuf::from_str(&output_dir).unwrap();
        write_file(&mut output_dir, "evm_verifier.bin", &deployment_code);

        // Dump public input data.
        let pi_data: Vec<_> = proof
            .instances()
            .iter()
            .flatten()
            .flat_map(|value| value.to_repr().as_ref().iter().rev().cloned().collect_vec())
            .collect();
        write_file(&mut output_dir, "evm_pi_data.data", &pi_data);

        // Dump proof.
        let proof_data = proof.proof().to_vec();
        write_file(&mut output_dir, "evm_proof.data", &proof_data);

        evm_verify(deployment_code, proof.instances(), proof_data);
    }
}
