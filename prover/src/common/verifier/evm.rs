use super::Verifier;
use crate::{io::write_file, EvmProof};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use itertools::Itertools;
use snark_verifier::{
    pcs::kzg::{Bdfg21, Kzg},
    util::arithmetic::PrimeField,
};
use snark_verifier_sdk::{evm_verify, gen_evm_verifier, CircuitExt};
use std::{path::PathBuf, str::FromStr};

impl<C: CircuitExt<Fr>> Verifier<C> {
    // Should panic if failed to verify.
    pub fn evm_verify(&self, evm_proof: &EvmProof, output_dir: &str) {
        let mut yul_file_path = PathBuf::from_str(output_dir).unwrap();
        yul_file_path.push("evm_verifier.yul");

        // Generate deployment code and dump YUL file.
        let deployment_code = gen_evm_verifier::<C, Kzg<Bn256, Bdfg21>>(
            &self.params,
            &self.vk,
            evm_proof.num_instance.clone(),
            Some(yul_file_path.as_path()),
        );

        // Dump bytecode.
        let mut output_dir = PathBuf::from_str(output_dir).unwrap();
        write_file(&mut output_dir, "evm_verifier.bin", &deployment_code);

        // Dump public input data.
        let pi_data: Vec<_> = evm_proof
            .proof
            .instances()
            .iter()
            .flatten()
            .flat_map(|value| value.to_repr().as_ref().iter().rev().cloned().collect_vec())
            .collect();
        write_file(&mut output_dir, "evm_pi_data.data", &pi_data);

        // Dump proof.
        let proof_data = evm_proof.proof.proof().to_vec();
        write_file(&mut output_dir, "evm_proof.data", &proof_data);

        evm_verify(deployment_code, evm_proof.proof.instances(), proof_data);
    }
}
