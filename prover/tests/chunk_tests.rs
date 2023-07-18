use aggregator::CompressionCircuit;
use prover::{
    common::{Prover, Verifier},
    config::{LAYER1_DEGREE, LAYER2_DEGREE, ZKEVM_DEGREES},
    test_util::{load_block_traces_for_test, PARAMS_DIR},
    utils::{chunk_trace_to_witness_block, init_env_and_log},
};

#[cfg(feature = "prove_verify")]
#[test]
fn test_chunk_prove_verify() {
    // Init, load block traces and construct prover.

    let output_dir = init_env_and_log("comp_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_trace = load_block_traces_for_test().1;
    log::info!("Loaded chunk-trace");

    let witness_block = chunk_trace_to_witness_block(chunk_trace).unwrap();
    log::info!("Got witness-block");

    let mut prover = Prover::from_params_dir(PARAMS_DIR, &*ZKEVM_DEGREES);
    log::info!("Constructed prover");

    // Load or generate inner snark.
    let inner_snark = prover
        .load_or_gen_inner_snark("layer0", witness_block, Some(&output_dir))
        .unwrap();
    log::info!("Got inner-snark");

    // Load or generate compression wide snark (layer-1).
    let layer1_snark = prover
        .load_or_gen_comp_snark(
            "layer1_0",
            "layer1",
            true,
            *LAYER1_DEGREE,
            inner_snark,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression-wide-snark (layer-1)");

    // Load or generate compression EVM proof (layer-2).
    let proof = prover
        .gen_comp_evm_proof(
            "layer2_0",
            "layer2",
            false,
            *LAYER2_DEGREE,
            layer1_snark,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression-EVM-proof (layer-2)");

    // Construct verifier and EVM verify.
    let params = prover.params(*LAYER2_DEGREE).clone();
    let vk = proof.vk::<CompressionCircuit>();
    let verifier = Verifier::new(params, vk);
    verifier.evm_verify::<CompressionCircuit>(&proof, &output_dir);
    log::info!("Finish EVM verify");
}
