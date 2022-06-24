use crate::circuit::{create_evm_circuit, create_state_circuit};
use halo2_proofs::pairing::bn256::G1Affine;
use halo2_proofs::plonk::{keygen_pk, keygen_vk, Error, ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::Params;

/// generate evm_circuit verifying key
pub fn gen_evm_vk(params: &Params<G1Affine>) -> Result<VerifyingKey<G1Affine>, Error> {
    let evm_circuit = create_evm_circuit();
    keygen_vk(params, &evm_circuit)
}

/// generate evm_circuit proving key
pub fn gen_evm_pk(params: &Params<G1Affine>) -> Result<ProvingKey<G1Affine>, Error> {
    let evm_circuit = create_evm_circuit();
    let evm_vk = gen_evm_vk(params)?;
    keygen_pk(params, evm_vk, &evm_circuit)
}

/// generate state_circuit verifying key
pub fn gen_state_vk(params: &Params<G1Affine>) -> Result<VerifyingKey<G1Affine>, Error> {
    let state_circuit = create_state_circuit();
    keygen_vk(params, &state_circuit)
}

/// generate state_circuit proving key
pub fn gen_state_pk(params: &Params<G1Affine>) -> Result<ProvingKey<G1Affine>, Error> {
    let state_vk = gen_state_vk(params)?;
    let state_circuit = create_state_circuit();
    keygen_pk(params, state_vk, &state_circuit)
}
