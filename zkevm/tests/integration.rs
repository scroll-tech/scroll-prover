use std::sync::Once;

const PARAMS_DIR: &str = "./test_params";
const SEED_PATH: &str = "./test_seed";
static ENV_LOGGER: Once = Once::new();

fn parse_trace_path_from_env(mode: &str) -> &'static str {
    let trace_path = match mode {
        "empty" => "./tests/trace-empty.json",
        "greeter" => "./tests/trace-greeter.json",
        "multiple" => "./tests/trace-multiple-erc20.json",
        "native" => "./tests/trace-native-transfer.json",
        "single" => "./tests/trace-single-erc20.json",
        "dao" => "./tests/trace-dao.json",
        "nft" => "./tests/trace-nft.json",
        "sushi" => "./tests/trace-masterchef.json",
        "bridge" => "./tests/trace-bridge.json",
        _ => "./tests/trace-multiple-erc20.json",
    };
    log::info!("using mode {:?}, testing with {:?}", mode, trace_path);
    trace_path
}

fn init() {
    ENV_LOGGER.call_once(env_logger::init);
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_evm_prove_verify() {
    use std::time::Instant;

    use zkevm::{
        circuit::{EvmCircuit, DEGREE},
        prover::Prover,
        utils::{
            get_block_result_from_file, load_or_create_params, load_or_create_seed, read_env_var,
        },
        verifier::Verifier,
    };

    dotenv::dotenv().ok();
    init();
    let trace_path = parse_trace_path_from_env(&read_env_var("MODE", "multiple".to_string()));

    let _ = load_or_create_params(PARAMS_DIR, *DEGREE).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let block_result = get_block_result_from_file(trace_path);

    log::info!("start generating evm_circuit proof");
    let now = Instant::now();
    let mut prover = Prover::from_fpath(PARAMS_DIR, SEED_PATH);
    let proof = prover
        .create_target_circuit_proof::<EvmCircuit, _>(&block_result)
        .unwrap();
    log::info!(
        "finish generating evm_circuit proof, cost {:?}",
        now.elapsed()
    );

    log::info!("start verifying evm_circuit proof");
    let now = Instant::now();
    let verifier = Verifier::from_fpath(PARAMS_DIR, None);
    log::info!(
        "finish verifying evm_circuit proof, cost {:?}",
        now.elapsed()
    );
    assert!(verifier
        .verify_target_circuit_proof::<EvmCircuit, _>(&proof)
        .is_ok());
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_state_prove_verify() {
    use std::time::Instant;

    use zkevm::{
        circuit::{StateCircuit, DEGREE},
        prover::Prover,
        utils::{
            get_block_result_from_file, load_or_create_params, load_or_create_seed, read_env_var,
        },
        verifier::Verifier,
    };

    dotenv::dotenv().ok();
    init();
    let trace_path = parse_trace_path_from_env(&read_env_var("MODE", "multiple".to_string()));

    let _ = load_or_create_params(PARAMS_DIR, *DEGREE).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let block_result = get_block_result_from_file(trace_path);

    log::info!("start generating state_circuit proof");
    let now = Instant::now();
    let mut prover = Prover::from_fpath(PARAMS_DIR, SEED_PATH);
    let proof = prover
        .create_target_circuit_proof::<StateCircuit, _>(&block_result)
        .unwrap();
    log::info!(
        "finish generating state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start verifying state_circuit proof");
    let now = Instant::now();
    let verifier = Verifier::from_fpath(PARAMS_DIR, None);
    log::info!(
        "finish verifying state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );
    assert!(verifier
        .verify_target_circuit_proof::<StateCircuit, _>(&proof)
        .is_ok());
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_state_evm_connect() {
    use std::time::Instant;

    use halo2_proofs::{
        pairing::bn256::G1Affine,
        transcript::{Challenge255, PoseidonRead, TranscriptRead},
    };
    use zkevm::{
        circuit::{EvmCircuit, StateCircuit, DEGREE},
        prover::Prover,
        utils::{get_block_result_from_file, load_or_create_params, load_or_create_seed},
        verifier::Verifier,
    };

    dotenv::dotenv().ok();
    init();

    log::info!("loading setup params");
    let _ = load_or_create_params(PARAMS_DIR, *DEGREE).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let trace_path = parse_trace_path_from_env("greeter");
    let block_result = get_block_result_from_file(trace_path);

    let mut prover = Prover::from_fpath(PARAMS_DIR, SEED_PATH);
    let verifier = Verifier::from_fpath(PARAMS_DIR, None);

    log::info!("start generating state_circuit proof");
    let now = Instant::now();
    let state_proof = prover
        .create_target_circuit_proof::<StateCircuit, _>(&block_result)
        .unwrap();
    log::info!(
        "finish generating state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start verifying state_circuit proof");
    let now = Instant::now();
    assert!(verifier
        .verify_target_circuit_proof::<StateCircuit, _>(&state_proof)
        .is_ok());
    log::info!(
        "finish verifying state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start generating evm_circuit proof");
    let now = Instant::now();
    let evm_proof = prover
        .create_target_circuit_proof::<EvmCircuit, _>(&block_result)
        .unwrap();
    log::info!(
        "finish generating evm_circuit proof, cost {:?}",
        now.elapsed()
    );

    log::info!("start verifying evm_circuit proof");
    let now = Instant::now();
    assert!(verifier
        .verify_target_circuit_proof::<EvmCircuit, _>(&evm_proof)
        .is_ok());
    log::info!(
        "finish verifying evm_circuit proof, cost {:?}",
        now.elapsed()
    );

    let rw_commitment_state = {
        let mut transcript =
            PoseidonRead::<_, _, Challenge255<G1Affine>>::init(&state_proof.proof[..]);
        transcript.read_point().unwrap()
    };
    log::info!("rw_commitment_state {:?}", rw_commitment_state);

    let rw_commitment_evm = {
        let mut transcript =
            PoseidonRead::<_, _, Challenge255<G1Affine>>::init(&evm_proof.proof[..]);
        transcript.read_point().unwrap()
    };
    log::info!("rw_commitment_evm {:?}", rw_commitment_evm);

    assert_eq!(rw_commitment_evm, rw_commitment_state);
    log::info!("Same commitment! Test passes!");
}
