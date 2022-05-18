use types::eth::mock_block_result;
use zkevm::prover::Prover;
use zkevm::utils::{load_or_create_params, load_or_create_seed};
use zkevm::verifier::Verifier;

const PARAMS_PATH: &str = "./test_params";
const SEED_PATH: &str = "./test_seed";

#[cfg(feature = "prove_verify")]
#[test]
fn test_evm_prove_verify() {
    let _ = load_or_create_params(PARAMS_PATH).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let block_result = mock_block_result();

    let prover = Prover::with_fpath(PARAMS_PATH, SEED_PATH);
    let proof = prover.create_evm_proof(&block_result).unwrap();

    let verifier = Verifier::with_fpath(PARAMS_PATH);
    assert!(verifier.verify_evm_proof(proof, &block_result));
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_state_prove_verify() {
    let _ = load_or_create_params(PARAMS_PATH).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let block_result = mock_block_result();

    let prover = Prover::with_fpath(PARAMS_PATH, SEED_PATH);
    let proof = prover.create_state_proof(&block_result).unwrap();

    let verifier = Verifier::with_fpath(PARAMS_PATH);
    assert!(verifier.verify_state_proof(proof, &block_result));
}
