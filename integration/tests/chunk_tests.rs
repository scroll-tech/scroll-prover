use integration::test_util::{ASSETS_DIR, PARAMS_DIR};
use prover::utils::init_env_and_log;

#[cfg(feature = "prove_verify")]
#[test]
fn test_chunk_prove_verify() {
    use integration::test_util::{load_chunk, prove_and_verify_chunk, trace_path_for_test};
    use prover::ChunkProvingTask;

    let output_dir = init_env_and_log("chunk_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let trace_path = trace_path_for_test();
    let traces = load_chunk(&trace_path).1;
    let chunk = ChunkProvingTask::from(traces);
    prove_and_verify_chunk(chunk, None, PARAMS_DIR, ASSETS_DIR, &output_dir);
}
