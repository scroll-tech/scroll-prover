use integration::test_util::{load_chunk_for_test, ASSETS_DIR, PARAMS_DIR};
use prover::{
    utils::init_env_and_log,
    zkevm::{Prover, Verifier},
};
use std::env;

#[cfg(feature = "prove_verify")]
#[test]
fn test_chunk_prove_verify() {
    use prover::ChunkProvingTask;

    let output_dir = init_env_and_log("chunk_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_trace = load_chunk_for_test().1;
    log::info!("Loaded chunk trace");

    let mut zkevm_prover = Prover::from_dirs(PARAMS_DIR, ASSETS_DIR);
    log::info!("Constructed zkevm prover");

    let chunk_proof = zkevm_prover
        .gen_chunk_proof(
            ChunkProvingTask::from(chunk_trace),
            None,
            None,
            Some(&output_dir),
        )
        .unwrap();

    // output_dir is used to load chunk vk
    env::set_var("CHUNK_VK_FILENAME", "vk_chunk_0.vkey");
    let verifier = Verifier::from_dirs(PARAMS_DIR, &output_dir);
    assert!(verifier.verify_chunk_proof(chunk_proof));
}
