use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Once;
use std::time::Instant;
use types::eth::BlockResult;
use zkevm::prover::Prover;
use zkevm::utils::{load_or_create_params, load_or_create_seed};
use zkevm::verifier::Verifier;

const PARAMS_PATH: &str = "./test_params";
const SEED_PATH: &str = "./test_seed";
const TRACE_PATH: &str = "./tests/trace.json";
static ENV_LOGGER: Once = Once::new();

fn init() {
    ENV_LOGGER.call_once(|| env_logger::init());
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_evm_prove_verify() {
    dotenv::dotenv().ok();
    init();

    let _ = load_or_create_params(PARAMS_PATH).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let block_result = get_block_result_from_file(TRACE_PATH);

    log::info!("start generating evm proof");
    let now = Instant::now();
    let prover = Prover::from_fpath(PARAMS_PATH, SEED_PATH);
    let proof = prover.create_evm_proof(&block_result).unwrap();
    log::info!("finish generating evm proof, cost {:?}", now.elapsed());

    log::info!("start verifying evm proof");
    let now = Instant::now();
    let verifier = Verifier::from_fpath(PARAMS_PATH);
    log::info!("finish verifying evm proof, cost {:?}", now.elapsed());
    assert!(verifier.verify_evm_proof(proof, &block_result));
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_state_prove_verify() {
    dotenv::dotenv().ok();
    init();

    let _ = load_or_create_params(PARAMS_PATH).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let block_result = get_block_result_from_file(TRACE_PATH);

    log::info!("start generating state proof");
    let now = Instant::now();
    let prover = Prover::from_fpath(PARAMS_PATH, SEED_PATH);
    let proof = prover.create_state_proof(&block_result).unwrap();
    log::info!(
        "finish generating state proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start verifying state proof");
    let now = Instant::now();
    let verifier = Verifier::from_fpath(PARAMS_PATH);
    log::info!("finish verifying state proof, elapsed: {:?}", now.elapsed());
    assert!(verifier.verify_state_proof(proof, &block_result));
}

fn get_block_result_from_file<P: AsRef<Path>>(path: P) -> BlockResult {
    let mut buffer = Vec::new();
    let mut f = File::open(path).unwrap();
    f.read_to_end(&mut buffer).unwrap();

    #[derive(Deserialize, Serialize, Default)]
    struct RpcJson {
        result: BlockResult,
    }

    let j = serde_json::from_slice::<RpcJson>(&buffer).unwrap();

    j.result
}
