use crate::circuit::{create_state_circuit, DEGREE};
use halo2_proofs::plonk::{keygen_pk, keygen_vk, Error, ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use pairing::bn256::{Fr, G1Affine};
use zkevm_circuits::evm_circuit::param::STEP_HEIGHT;
use zkevm_circuits::evm_circuit::table::FixedTableTag;
use zkevm_circuits::evm_circuit::test::TestCircuit;
use zkevm_circuits::evm_circuit::witness::Block;

/// generate (evm_pk, evm_vk)
pub fn gen_evm_key(
    params: &Params<G1Affine>,
) -> Result<(ProvingKey<G1Affine>, VerifyingKey<G1Affine>), Error> {
    let default_block = Block::<Fr> {
        step_num_with_pad: ((1 << DEGREE) - 64) / STEP_HEIGHT,
        ..Default::default()
    };

    let evm_circuit = TestCircuit::new(default_block, FixedTableTag::iterator().collect());
    let evm_vk = keygen_vk(&params, &evm_circuit)?;
    let evm_pk = keygen_pk(&params, evm_vk.clone(), &evm_circuit)?;
    Ok((evm_pk, evm_vk))
}

/// generate (state_pk, state_vk)
pub fn gen_state_key(
    params: &Params<G1Affine>,
) -> Result<(ProvingKey<G1Affine>, VerifyingKey<G1Affine>), Error> {
    let state_circuit = create_state_circuit();
    let state_vk = keygen_vk(&params, &state_circuit).unwrap();
    let state_pk = keygen_pk(&params, state_vk.clone(), &state_circuit).unwrap();
    Ok((state_pk, state_vk))
}
