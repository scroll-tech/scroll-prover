use std::time::Instant;
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

    log::info!("start generating evm proof");
    let prover = Prover::with_fpath(PARAMS_PATH, SEED_PATH);
    let proof = prover.create_evm_proof(&block_result).unwrap();
    log::info!("finish generating evm proof");

    log::info!("start verifying evm proof");
    let verifier = Verifier::with_fpath(PARAMS_PATH);
    log::info!("finish verifying evm proof");
    assert!(verifier.verify_evm_proof(proof, &block_result));
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_state_prove_verify() {
    let _ = load_or_create_params(PARAMS_PATH).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let block_result = mock_block_result();

    log::info!("start generating state proof");
    let now = Instant::now();
    let prover = Prover::with_fpath(PARAMS_PATH, SEED_PATH);
    let proof = prover.create_state_proof(&block_result).unwrap();
    log::info!(
        "finish generating state proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start verifying state proof");
    let now = Instant::now();
    let verifier = Verifier::with_fpath(PARAMS_PATH);
    log::info!("finish verifying state proof, elapsed: {:?}", now.elapsed());
    assert!(verifier.verify_state_proof(proof, &block_result));
}
