use integration::test_util::{ASSETS_DIR, PARAMS_DIR};
use prover::init_env_and_log;

#[cfg(feature = "prove_verify")]
#[test]
fn test_chunk_prove_verify() {
    use integration::{
        prove::prove_and_verify_chunk,
        test_util::{load_chunk, trace_path_for_test},
    };
    use itertools::Itertools;
    use prover::{ChunkProvingTask, CHUNK_PROVER_DEGREES};

    let output_dir = init_env_and_log("chunk_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let params_map = prover::Prover::load_params_map(
        PARAMS_DIR,
        &CHUNK_PROVER_DEGREES.iter().copied().collect_vec(),
    );

    let trace_path = trace_path_for_test();
    let traces = load_chunk(&trace_path).1;
    let chunk = ChunkProvingTask::new(traces);
    prove_and_verify_chunk(chunk, None, &params_map, ASSETS_DIR, &output_dir);
}
