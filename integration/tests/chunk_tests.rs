use integration::test_util::{ASSETS_DIR, PARAMS_DIR};
use prover::utils::init_env_and_log;
use integration::{
    prove::{prove_and_verify_chunk, prove_and_verify_sp1_chunk, SP1Prover},
    test_util::{load_chunk, trace_path_for_test},
};
use prover::{config::ZKEVM_DEGREES, ChunkProvingTask, zkevm::Prover as ChunkProver};

#[cfg(feature = "prove_verify")]
#[test]
fn test_chunk_prove_verify() {

    use itertools::Itertools;
    let output_dir = init_env_and_log("chunk_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let params_map = prover::common::Prover::load_params_map(
        PARAMS_DIR,
        &ZKEVM_DEGREES.iter().copied().collect_vec(),
    );

    let trace_path = trace_path_for_test();
    let traces = load_chunk(&trace_path).1;
    let chunk = ChunkProvingTask::from(traces);
    let mut prover = ChunkProver::from_params_and_assets(&params_map, ASSETS_DIR);
    log::info!("Constructed chunk prover");
    prove_and_verify_chunk(&params_map, &output_dir, chunk, &mut prover, None);
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_sp1_chunk_prove_verify() {
    use itertools::Itertools;
    let output_dir = init_env_and_log("chunk_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let params_map = prover::common::Prover::load_params_map(
        PARAMS_DIR,
        &ZKEVM_DEGREES.iter().copied().collect_vec(),
    );

    let trace_path = trace_path_for_test();
    let traces = load_chunk(&trace_path).1;
    let chunk = ChunkProvingTask::from(traces);
    let mut prover = SP1Prover::from_params_and_assets(&params_map, ASSETS_DIR);
    log::info!("Constructed sp1 chunk prover");
    prove_and_verify_sp1_chunk(&params_map, &output_dir, Some(&trace_path), chunk, &mut prover, None);

}
