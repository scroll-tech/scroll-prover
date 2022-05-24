use crate::circuit::{create_state_circuit, DEGREE};
use halo2_proofs::pairing::bn256::{Fr, G1Affine};
use halo2_proofs::plonk::{keygen_pk, keygen_vk, Circuit, Error, ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use strum::IntoEnumIterator;
use zkevm_circuits::evm_circuit::table::FixedTableTag;
use zkevm_circuits::evm_circuit::test::TestCircuit;
use zkevm_circuits::evm_circuit::witness::Block;

/// generate evm_circuit verifying key
pub fn gen_evm_vk(params: &Params<G1Affine>) -> Result<VerifyingKey<G1Affine>, Error> {
    keygen_vk(params, &test_circuit())
}

/// generate evm_circuit proving key
pub fn gen_evm_pk(params: &Params<G1Affine>) -> Result<ProvingKey<G1Affine>, Error> {
    let evm_vk = gen_evm_vk(params)?;
    keygen_pk(params, evm_vk, &test_circuit())
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

fn test_circuit() -> impl Circuit<Fr> {
    let default_block = Block::<Fr> {
        pad_to: (1 << DEGREE) - 64,
        ..Default::default()
    };

    TestCircuit::new(default_block, FixedTableTag::iter().collect())
}
