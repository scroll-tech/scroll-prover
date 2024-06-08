// Fast tests which can be finished within minutes

use integration::test_util::{
    ccc_as_signer, load_chunk_for_test, prepare_circuit_capacity_checker,
    run_circuit_capacity_checker,
};
use prover::{
    utils::{init_env_and_log, short_git_version},
    zkevm::circuit::{block_traces_to_witness_block, TargetCircuit},
};

#[test]
fn test_short_git_version() {
    init_env_and_log("integration");

    let git_version = short_git_version();
    log::info!("short_git_version = {git_version}");

    assert_eq!(git_version.len(), 7);
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
        run_circuit_capacity_checker(batch_id, chunk_id, &block_traces)
    } else {
        ccc_as_signer(chunk_id, &block_traces).1
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
