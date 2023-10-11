use integration::test_util::load_block_traces_for_test;
use prover::{inner::Prover, utils::init_env_and_log, zkevm::circuit::SuperCircuit};

#[cfg(feature = "prove_verify")]
#[test]
fn test_mock_prove() {
    init_env_and_log("mock_tests");

    let block_traces = load_block_traces_for_test().1;
    Prover::<SuperCircuit>::mock_prove_target_circuit_batch(block_traces).unwrap();
}
