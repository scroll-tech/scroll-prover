// Fast tests which can be finished within minutes

use integration::{
    capacity_checker::{
        ccc_as_signer_light, ccc_by_chunk, prepare_circuit_capacity_checker, run_circuit_capacity_checker, txbytx_traces_from_block, CCCMode
    },
    test_util::load_chunk_for_test,
};
use prover::{
    io::read_all,
    utils::{get_block_trace_from_file, init_env_and_log, short_git_version},
    zkevm::{circuit::{block_traces_to_witness_block, TargetCircuit}, CircuitCapacityChecker},
};

#[test]
fn test_short_git_version() {
    init_env_and_log("integration");

    let git_version = short_git_version();
    log::info!("short_git_version = {git_version}");

    assert_eq!(git_version.len(), 7);
}

#[ignore]
#[test]
fn test_evm_verifier() {
    init_env_and_log("test_evm_verifer");
    log::info!("cwd {:?}", std::env::current_dir());
    let version = "release-v0.11.1";
    let yul = read_all(&format!("../{version}/evm_verifier.yul"));
    //log::info!("yul len {}", yul.len());
    let pi = read_all(&format!("../{version}/pi_data.data"));
    let mut proof = read_all(&format!("../{version}/proof.data"));
    proof.splice(384..384, pi);
    log::info!("calldata len {}", proof.len());

    for version in [
        "0.8.19", "0.8.20", "0.8.21", "0.8.22", "0.8.23", "0.8.24", "0.8.25", "0.8.26",
    ] {
        use snark_verifier::loader::evm::compile_yul;
        use std::process::Command;
        Command::new("svm")
            .arg("use")
            .arg(version)
            .output()
            .expect("failed to execute process");
        log::info!("svm use {}", version);
        let bytecode = compile_yul(&String::from_utf8(yul.clone()).unwrap());
        log::info!("bytecode len {}", bytecode.len());
        match integration::evm::deploy_and_call(bytecode, proof.clone()) {
            Ok(gas) => log::info!("gas cost {gas}"),
            Err(e) => {
                panic!("test failed {e:#?}");
            }
        }
    }

    log::info!("check released bin");
    let bytecode = read_all(&format!("../{version}/evm_verifier.bin"));
    log::info!("bytecode len {}", bytecode.len());
    match integration::evm::deploy_and_call(bytecode, proof.clone()) {
        Ok(gas) => log::info!("gas cost {gas}"),
        Err(e) => {
            panic!("test failed {e:#?}");
        }
    }
}

// suppose a "proof.json" has been provided under the 'release'
// directory or the test would fail
#[ignore]
#[test]
fn test_evm_verifier_for_dumped_proof() {
    use prover::{io::from_json_file, proof::BundleProof};

    init_env_and_log("test_evm_verifer");
    log::info!("cwd {:?}", std::env::current_dir());
    let version = "release-v0.12.0-rc.2";

    let proof: BundleProof = from_json_file(&format!("../{version}/proof.json")).unwrap();

    let proof_dump = proof.clone().proof_to_verify();
    log::info!("pi dump {:#?}", proof_dump.instances());

    let proof = proof.calldata();
    log::info!("calldata len {}", proof.len());

    log::info!("check released bin");
    let bytecode = read_all(&format!("../{version}/evm_verifier.bin"));
    log::info!("bytecode len {}", bytecode.len());
    match integration::evm::deploy_and_call(bytecode, proof.clone()) {
        Ok(gas) => log::info!("gas cost {gas}"),
        Err(e) => {
            panic!("test failed {e:#?}");
        }
    }
}

// Make sure tx-by-tx light_mode=false row usage >= real row usage
#[test]
fn test_txbytx_traces() {
    init_env_and_log("integration");
    prepare_circuit_capacity_checker();

    use prover::BlockTrace;

    // part1: real row usage
    let batch_id = 0;
    let chunk_id = 0;
    let block_trace = get_block_trace_from_file("tests/test_data/ccc/8626705-legacy-block.json");
    let (real_usage, t) = ccc_by_chunk(batch_id, chunk_id, &[block_trace]);
    //log::info!("row usage {:#?}", real_usage);
    //log::info!("avg time each tx: {}ms", t.as_millis());

    // part2: tx by tx row usage
    let txbytx_traces: Vec<BlockTrace> = {
        let f = std::fs::File::open("tests/test_data/ccc/8626705-legacy-txbytx.json").unwrap();
        serde_json::from_reader(&f).unwrap()
    };
    let tx_num = txbytx_traces.len();

    let mut checker = CircuitCapacityChecker::new();
    checker.light_mode = false;
    let start_time = std::time::Instant::now();
    for tx in txbytx_traces {
        checker.estimate_circuit_capacity(tx).unwrap();
    }
    let row_usage = checker.get_acc_row_usage(false);
    let avg_ccc_time = start_time.elapsed().as_millis() / tx_num as u128;
    //log::info!("row usage {:#?}", row_usage);
    //log::info!("avg time each tx: {avg_ccc_time}ms");

    // part3: pretty print
    log::info!("circuit\ttxbytx\tblock");
    for i in 0..real_usage.row_usage_details.len() {
        let r1 = row_usage.row_usage_details[i].row_number;
        let r2 = real_usage.row_usage_details[i].row_number;
        // FIXME: the "1" of bytecode circuit
        assert!(r1 + 1 >= r2);
        log::info!("{}\t{}\t{}", row_usage.row_usage_details[i].name, 
            r1, r2
            );
    }
    log::info!("{}\t{}\t{}", "avg-tx-ms", t.as_millis(), avg_ccc_time);
}

#[test]
fn test_capacity_checker() {
    init_env_and_log("integration");
    prepare_circuit_capacity_checker();

    let block_traces = load_chunk_for_test().1;

    let full = true;
    let batch_id = 0;
    let chunk_id = 0;
    let avg_each_tx_time = if full {
        let ccc_modes = [
            //CCCMode::Optimal,
            //CCCMode::SignerLight,
            CCCMode::SignerFull,
            //CCCMode::FollowerLight,
            CCCMode::FollowerFull,
        ];
        run_circuit_capacity_checker(batch_id, chunk_id, &block_traces, &ccc_modes).unwrap()
    } else {
        ccc_as_signer_light(chunk_id, &block_traces).1
    };
    log::info!("avg_each_tx_time {avg_each_tx_time:?}");
}

#[test]
fn estimate_circuit_rows() {
    init_env_and_log("integration");
    prepare_circuit_capacity_checker();

    let (_, block_trace) = load_chunk_for_test();
    let witness_block = block_traces_to_witness_block(block_trace).unwrap();
    log::info!("estimating used rows");
    let row_usage = <prover::zkevm::circuit::SuperCircuit as TargetCircuit>::Inner::min_num_rows_block_subcircuits(&witness_block);
    let r = row_usage
        .iter()
        .max_by_key(|x| x.row_num_real)
        .unwrap()
        .clone();
    log::info!("final rows: {} {}", r.row_num_real, r.name);
}
