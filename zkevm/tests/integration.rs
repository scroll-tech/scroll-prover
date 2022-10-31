use chrono::Utc;
use types::eth::BlockResult;
use zkevm::{
    circuit::TargetCircuit,
    prover::Prover,
    utils::{get_block_result_from_file, read_env_var},
};

mod test_util;
use test_util::{init, parse_trace_path_from_mode, PARAMS_DIR, SEED_PATH};

#[test]
fn estimate_circuit_rows() {
    use zkevm::{
        circuit::{self, TargetCircuit, DEGREE},
        utils::{load_or_create_params, load_or_create_seed},
    };

    init();
    let _ = load_or_create_params(PARAMS_DIR, *DEGREE).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let block_result = load_block_result_for_test();

    log::info!("estimating used rows for current block");
    log::info!(
        "evm circuit: {}",
        circuit::EvmCircuit::estimate_rows(&block_result)
    );
    log::info!(
        "state circuit: {}",
        circuit::StateCircuit::estimate_rows(&block_result)
    );
    log::info!(
        "storage circuit: {}",
        circuit::ZktrieCircuit::estimate_rows(&block_result)
    );
    log::info!(
        "hash circuit: {}",
        circuit::PoseidonCircuit::estimate_rows(&block_result)
    );
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_evm_prove_verify() {
    use zkevm::circuit::EvmCircuit;
    test_target_circuit_prove_verify::<EvmCircuit>();
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_state_prove_verify() {
    use zkevm::circuit::StateCircuit;
    test_target_circuit_prove_verify::<StateCircuit>();
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_storage_prove_verify() {
    use zkevm::circuit::ZktrieCircuit;
    test_target_circuit_prove_verify::<ZktrieCircuit>();
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_hash_prove_verify() {
    use zkevm::circuit::PoseidonCircuit;
    test_target_circuit_prove_verify::<PoseidonCircuit>();
}

fn test_mock_prove_all_with_circuit<C: TargetCircuit>(
    trace_paths: &[String],
) -> Vec<(String, String)> {
    let mut failed_cases = Vec::new();
    for trace_path in trace_paths {
        log::info!("test {} circuit with {}", C::name(), trace_path);
        let block_result = get_block_result_from_file(trace_path);
        let full_height_mock_prove = true;
        let result = Prover::mock_prove_target_circuit::<C>(&block_result, full_height_mock_prove);
        log::info!(
            "test {} circuit with {} result: {:?}",
            C::name(),
            trace_path,
            result
        );
        if result.is_err() {
            failed_cases.push((C::name(), trace_path.to_string()));
        }
    }
    log::info!("ALL {} circuit tests finished", C::name());
    failed_cases
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_mock_prove_all_target_circuits_packing() {
    use zkevm::circuit::{EvmCircuit, PoseidonCircuit, StateCircuit, ZktrieCircuit};

    init();
    let mut block_results = Vec::new();
    for block_number in 1..=16 {
        let trace_path = format!("tests/traces/bridge/{:02}.json", block_number);
        let block_result = get_block_result_from_file(trace_path);
        block_results.push(block_result);
    }
    Prover::mock_prove_target_circuit_multi::<StateCircuit>(&block_results, true).unwrap();
    Prover::mock_prove_target_circuit_multi::<EvmCircuit>(&block_results, true).unwrap();
    Prover::mock_prove_target_circuit_multi::<ZktrieCircuit>(&block_results, true).unwrap();
    Prover::mock_prove_target_circuit_multi::<PoseidonCircuit>(&block_results, true).unwrap();
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_mock_prove_all_target_circuits() {
    use glob::glob;
    use zkevm::circuit::{EvmCircuit, PoseidonCircuit, StateCircuit, ZktrieCircuit};

    init();
    let test_trace: String = read_env_var("TEST_TRACE", "./tests/traces".to_string());

    let paths: Vec<String> = if std::fs::metadata(&test_trace).unwrap().is_dir() {
        glob(&format!("{}/**/*.json", test_trace))
            .unwrap()
            .map(|p| p.unwrap().to_str().unwrap().to_string())
            .collect()
    } else {
        vec![test_trace]
    };
    log::info!("test cases traces: {:?}", paths);
    let paths = &paths;
    let mut failed_cases = Vec::new();
    failed_cases.append(&mut test_mock_prove_all_with_circuit::<StateCircuit>(paths));
    failed_cases.append(&mut test_mock_prove_all_with_circuit::<EvmCircuit>(paths));
    failed_cases.append(&mut test_mock_prove_all_with_circuit::<ZktrieCircuit>(
        paths,
    ));
    failed_cases.append(&mut test_mock_prove_all_with_circuit::<PoseidonCircuit>(
        paths,
    ));
    assert_eq!(failed_cases, Vec::new());
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_state_evm_connect() {
    // TODO: better code reuse
    use std::time::Instant;

    use halo2_proofs::{
        halo2curves::bn256::G1Affine,
        transcript::{Challenge255, PoseidonRead, TranscriptRead},
    };
    use zkevm::{
        circuit::{EvmCircuit, StateCircuit, DEGREE},
        prover::Prover,
        utils::{get_block_result_from_file, load_or_create_params, load_or_create_seed},
        verifier::Verifier,
    };

    init();

    log::info!("loading setup params");
    let _ = load_or_create_params(PARAMS_DIR, *DEGREE).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let trace_path = parse_trace_path_from_mode("greeter");
    let block_result = get_block_result_from_file(trace_path);

    let mut prover = Prover::from_fpath(PARAMS_DIR, SEED_PATH);
    let mut verifier = Verifier::from_fpath(PARAMS_DIR, None);

    log::info!("start generating state_circuit proof");
    let now = Instant::now();
    let state_proof = prover
        .create_target_circuit_proof::<StateCircuit>(&block_result)
        .unwrap();
    log::info!(
        "finish generating state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start verifying state_circuit proof");
    let now = Instant::now();
    assert!(verifier
        .verify_target_circuit_proof::<StateCircuit>(&state_proof)
        .is_ok());
    log::info!(
        "finish verifying state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start generating evm_circuit proof");
    let now = Instant::now();
    let evm_proof = prover
        .create_target_circuit_proof::<EvmCircuit>(&block_result)
        .unwrap();
    log::info!(
        "finish generating evm_circuit proof, cost {:?}",
        now.elapsed()
    );

    log::info!("start verifying evm_circuit proof");
    let now = Instant::now();
    assert!(verifier
        .verify_target_circuit_proof::<EvmCircuit>(&evm_proof)
        .is_ok());
    log::info!(
        "finish verifying evm_circuit proof, cost {:?}",
        now.elapsed()
    );

    let load_commitments = |proof: &[u8], start, len| {
        let mut transcript = PoseidonRead::<_, _, Challenge255<G1Affine>>::init(proof);
        let mut points = Vec::new();
        for _ in 0..start {
            transcript.read_point().unwrap();
        }
        for _ in 0..len {
            points.push(transcript.read_point().unwrap());
        }
        points
    };

    let rw_table_commitments_len = 11;
    let rw_table_start_evm = 0;
    let rw_table_start_state = 0;
    let rw_commitment_state = load_commitments(
        &state_proof.proof[..],
        rw_table_start_state,
        rw_table_commitments_len,
    );
    log::info!("rw_commitment_state {:?}", rw_commitment_state);

    let rw_commitment_evm = load_commitments(
        &evm_proof.proof[..],
        rw_table_start_evm,
        rw_table_commitments_len,
    );
    log::info!("rw_commitment_evm {:?}", rw_commitment_evm);

    assert_eq!(rw_commitment_evm, rw_commitment_state);
    log::info!("Same commitment! Test passes!");
}

fn test_target_circuit_prove_verify<C: TargetCircuit>() {
    use std::time::Instant;

    use zkevm::verifier::Verifier;

    init();

    let block_result = load_block_result_for_test();

    log::info!("start generating {} proof", C::name());
    let now = Instant::now();
    let mut prover = Prover::from_fpath(PARAMS_DIR, SEED_PATH);
    let proof = prover
        .create_target_circuit_proof::<C>(&block_result)
        .unwrap();
    log::info!("finish generating proof, elapsed: {:?}", now.elapsed());

    let output_file = format!(
        "/tmp/{}_{}.json",
        C::name(),
        Utc::now().format("%Y%m%d_%H%M%S")
    );
    let mut fd = std::fs::File::create(&output_file).unwrap();
    serde_json::to_writer_pretty(&mut fd, &proof).unwrap();
    log::info!("write proof to {}", output_file);

    log::info!("start verifying proof");
    let now = Instant::now();
    let mut verifier = Verifier::from_fpath(PARAMS_DIR, None);
    assert!(verifier.verify_target_circuit_proof::<C>(&proof).is_ok());
    log::info!("finish verifying proof, elapsed: {:?}", now.elapsed());
}

fn load_block_result_for_test() -> BlockResult {
    let mut trace_path = read_env_var("TRACE_FILE", "".to_string());
    if trace_path.is_empty() {
        trace_path =
            parse_trace_path_from_mode(&read_env_var("MODE", "multiple".to_string())).to_string();
    }
    get_block_result_from_file(trace_path)
}
