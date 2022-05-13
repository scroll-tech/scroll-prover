use halo2_proofs::plonk::{ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use pairing::bn256::G1Affine;
use rand_xorshift::XorShiftRng;
use types::eth::test::mock_block_result;
use zkevm::keygen::{gen_evm_pk, gen_evm_vk, gen_state_pk, gen_state_vk};
use zkevm::prover::Prover;
use zkevm::utils::{load_or_create_params, load_or_create_rng};
use zkevm::verifier::Verifier;

const PARAMS_PATH: &str = "./test_params";
const RNG_PATH: &str = "./test_rng.json";

#[cfg(feature = "prove_verify")]
#[test]
fn test_evm_prove_verify() {
    let _ = load_or_create_params(PARAMS_PATH).unwrap();
    let _ = load_or_create_rng(RNG_PATH).unwrap();

    let block_result = mock_block_result();

    let prover = Prover::with_fpath(PARAMS_PATH, RNG_PATH);
    let proof = prover.create_evm_proof(&block_result).unwrap();

    let verifier = Verifier::with_fpath(PARAMS_PATH);
    assert!(verifier.verify_evm_proof(proof, &block_result));
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_state_prove_verify() {
    let _ = load_or_create_params(PARAMS_PATH).unwrap();
    let _: XorShiftRng = load_or_create_rng(RNG_PATH).unwrap();

    let block_result = mock_block_result();

    let prover = Prover::with_fpath(PARAMS_PATH, RNG_PATH);
    let proof = prover.create_state_proof(&block_result).unwrap();

    let verifier = Verifier::with_fpath(PARAMS_PATH);
    assert!(verifier.verify_state_proof(proof, &block_result));
}
