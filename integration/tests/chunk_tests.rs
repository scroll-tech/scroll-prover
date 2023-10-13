use integration::test_util::{
    gen_and_verify_chunk_proofs, load_block_traces_for_test, ASSETS_DIR, PARAMS_DIR,
};
use prover::{
    utils::{chunk_trace_to_witness_block, init_env_and_log},
    zkevm::Prover,
};
use std::env;

#[cfg(feature = "prove_verify")]
#[test]
fn test_chunk_prove_verify() {
    let output_dir = init_env_and_log("chunk_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_trace = load_block_traces_for_test().1;
    log::info!("Loaded chunk trace");

    loop {
        let witness_block = chunk_trace_to_witness_block(chunk_trace.clone()).unwrap();
        log::info!("Got witness block");

        env::set_var("CHUNK_VK_FILENAME", "vk_chunk_0.vkey");
        let mut zkevm_prover = Prover::from_dirs(PARAMS_DIR, ASSETS_DIR);
        log::info!("Constructed zkevm prover");

        // Load or generate compression wide snark (layer-1).
        let layer1_snark = zkevm_prover
            .inner
            .load_or_gen_last_chunk_snark("layer1", &witness_block, None, Some(&output_dir))
            .unwrap();

        gen_and_verify_chunk_proofs(&mut zkevm_prover, layer1_snark, &output_dir);
    }
}
