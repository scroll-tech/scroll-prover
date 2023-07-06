use super::Proof;
use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::evm_verify;

pub struct EvmVerifier {
    bytecode: Vec<u8>,
}

impl EvmVerifier {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    /// Verifies the proof with EVM byte code. Panics if verification fails.
    pub fn verify(&self, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
        evm_verify(self.bytecode.clone(), instances, proof)
    }

    /// Verifies the proof with EVM byte code. Panics if verification fails.
    pub fn verify_proof(&self, proof: Proof) {
        let instances = proof.instances();
        evm_verify(self.bytecode.clone(), instances, proof.proof().to_vec())
    }
}
