use crate::circuit::{create_state_circuit, DEGREE};
use halo2_proofs::plonk::{keygen_pk, keygen_vk, Circuit, Error, ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use pairing::bn256::{Fr, G1Affine};
use zkevm_circuits::evm_circuit::param::STEP_HEIGHT;
use zkevm_circuits::evm_circuit::table::FixedTableTag;
use zkevm_circuits::evm_circuit::test::TestCircuit;
use zkevm_circuits::evm_circuit::witness::Block;

/// generate evm verifying key
pub fn gen_evm_vk(params: &Params<G1Affine>) -> Result<VerifyingKey<G1Affine>, Error> {
    keygen_vk(params, &test_circuit())
}

/// generate evm proving key
pub fn gen_evm_pk(params: &Params<G1Affine>) -> Result<ProvingKey<G1Affine>, Error> {
    let evm_vk = gen_evm_vk(params)?;
    keygen_pk(params, evm_vk, &test_circuit())
}

/// generate state verifying key
pub fn gen_state_vk(params: &Params<G1Affine>) -> Result<VerifyingKey<G1Affine>, Error> {
    let state_circuit = create_state_circuit();
    keygen_vk(params, &state_circuit)
}

pub fn gen_state_pk(params: &Params<G1Affine>) -> Result<ProvingKey<G1Affine>, Error> {
    let state_vk = gen_state_vk(params)?;
    let state_circuit = create_state_circuit();
    keygen_pk(params, state_vk, &state_circuit)
}

fn test_circuit() -> impl Circuit<Fr> {
    let default_block = Block::<Fr> {
        step_num_with_pad: ((1 << DEGREE) - 64) / STEP_HEIGHT,
        ..Default::default()
    };

    TestCircuit::new(default_block, FixedTableTag::iterator().collect())
}
