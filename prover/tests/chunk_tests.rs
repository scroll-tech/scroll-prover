use aggregator::CompressionCircuit;
use prover::{
    config::LAYER2_DEGREE,
    test_util::{load_block_traces_for_test, PARAMS_DIR},
    utils::{chunk_trace_to_witness_block, init_env_and_log},
    zkevm::{Prover, Verifier},
    Proof,
};

#[cfg(feature = "prove_verify")]
#[test]
fn test_chunk_prove_verify() {
    let test_name = "chunk_tests";
    let output_dir = init_env_and_log(test_name);
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_trace = load_block_traces_for_test().1;
    log::info!("Loaded chunk-trace");

    let witness_block = chunk_trace_to_witness_block(chunk_trace).unwrap();
    log::info!("Got witness block");

    let mut prover = Prover::from_params_dir(PARAMS_DIR);
    log::info!("Constructed prover");

    // Load or generate compression wide snark (layer-1).
    let layer1_snark = prover
        .load_or_gen_last_snark(test_name, witness_block, Some(&output_dir))
        .unwrap();

    // Load or generate compression thin snark (layer-2).
    let layer2_snark = prover
        .inner
        .load_or_gen_comp_snark(
            test_name,
            "layer2",
            false,
            *LAYER2_DEGREE,
            layer1_snark.clone(),
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression thin snark (layer-2)");

    let proof = Proof::from_snark(prover.inner.pk("layer2").unwrap(), &layer2_snark).unwrap();
    log::info!("Got normal proof");

    let params = prover.inner.params(*LAYER2_DEGREE).clone();
    let vk = prover.inner.pk("layer2").unwrap().get_vk().clone();
    let verifier = Verifier::new(params, vk);
    log::info!("Constructed verifier");

    assert!(verifier.verify_chunk_proof(proof));
    log::info!("Finish normal verification");

    // Load or generate compression EVM proof (layer-2).
    let proof = prover
        .inner
        .load_or_gen_comp_evm_proof(
            test_name,
            "layer2",
            false,
            *LAYER2_DEGREE,
            layer1_snark,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression-EVM-proof (layer-2)");

    verifier
        .inner
        .evm_verify::<CompressionCircuit>(&proof, &output_dir);
    log::info!("Finish EVM verification");
}
