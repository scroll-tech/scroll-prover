use integration::test_util::load_chunk_for_test;
#[cfg(feature = "prove_verify")]
#[test]
fn test_mock_prove() {
    use integration::mock::mock_prove_target_circuit_chunk;
    use prover::init_env_and_log;

    init_env_and_log("mock_tests");

    let block_traces = load_chunk_for_test().1;
    mock_prove_target_circuit_chunk(block_traces).unwrap();
}
