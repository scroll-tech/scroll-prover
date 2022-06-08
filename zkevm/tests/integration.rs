use std::sync::Once;
use std::time::Instant;
use zkevm::prover::Prover;
use zkevm::utils::{get_block_result_from_file, load_or_create_params, load_or_create_seed};
use zkevm::verifier::Verifier;

const PARAMS_PATH: &str = "./test_params";
const SEED_PATH: &str = "./test_seed";
const TRACE_PATH: &str = "./tests/trace.json";
static ENV_LOGGER: Once = Once::new();

fn init() {
    ENV_LOGGER.call_once(env_logger::init);
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_evm_prove_verify() {
    dotenv::dotenv().ok();
    init();

    let _ = load_or_create_params(PARAMS_PATH).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let block_result = get_block_result_from_file(TRACE_PATH);

    log::info!("start generating evm_circuit proof");
    let now = Instant::now();
    let prover = Prover::from_fpath(PARAMS_PATH, SEED_PATH);
    let proof = prover.create_evm_proof(&block_result).unwrap();
    log::info!(
        "finish generating evm_circuit proof, cost {:?}",
        now.elapsed()
    );

    log::info!("start verifying evm_circuit proof");
    let now = Instant::now();
    let verifier = Verifier::from_fpath(PARAMS_PATH);
    log::info!(
        "finish verifying evm_circuit proof, cost {:?}",
        now.elapsed()
    );
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

    log::info!("start generating state_circuit proof");
    let now = Instant::now();
    let prover = Prover::from_fpath(PARAMS_PATH, SEED_PATH);
    let proof = prover.create_state_proof(&block_result).unwrap();
    log::info!(
        "finish generating state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start verifying state_circuit proof");
    let now = Instant::now();
    let verifier = Verifier::from_fpath(PARAMS_PATH);
    log::info!(
        "finish verifying state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );
    assert!(verifier.verify_state_proof(proof, &block_result));
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_state_evm_connect() {
    use halo2_proofs::{
        pairing::bn256::G1Affine,
        transcript::{Blake2bRead, Challenge255, TranscriptRead},
    };

    dotenv::dotenv().ok();
    init();

    log::info!("loading setup params");
    let _ = load_or_create_params(PARAMS_PATH).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let block_result = get_block_result_from_file(TRACE_PATH);

    let prover = Prover::from_fpath(PARAMS_PATH, SEED_PATH);
    let verifier = Verifier::from_fpath(PARAMS_PATH);

    log::info!("start generating state_circuit proof");
    let now = Instant::now();
    let state_proof = prover.create_state_proof(&block_result).unwrap();
    log::info!(
        "finish generating state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start verifying state_circuit proof");
    let now = Instant::now();
    assert!(verifier.verify_state_proof(state_proof.clone(), &block_result));
    log::info!(
        "finish verifying state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start generating evm_circuit proof");
    let now = Instant::now();
    let evm_proof = prover.create_evm_proof(&block_result).unwrap();
    log::info!(
        "finish generating evm_circuit proof, cost {:?}",
        now.elapsed()
    );

    log::info!("start verifying evm_circuit proof");
    let now = Instant::now();
    assert!(verifier.verify_evm_proof(evm_proof.clone(), &block_result));
    log::info!(
        "finish verifying evm_circuit proof, cost {:?}",
        now.elapsed()
    );

    let rw_commitment_state = {
        let mut transcript = Blake2bRead::<_, _, Challenge255<G1Affine>>::init(&state_proof[..]);
        transcript.read_point().unwrap()
    };
    println!("rw_commitment_state {:?}", rw_commitment_state);

    let rw_commitment_evm = {
        let mut transcript = Blake2bRead::<_, _, Challenge255<G1Affine>>::init(&evm_proof[..]);
        transcript.read_point().unwrap()
    };
    println!("rw_commitment_evm {:?}", rw_commitment_evm);

    assert_eq!(rw_commitment_evm, rw_commitment_state);
}
