use aggregator::CompressionCircuit;
use prover::{
    aggregator::{Prover, Verifier},
    test_util::{
        aggregator::{load_or_gen_chunk_snark, load_or_gen_comp_evm_proof, load_or_gen_comp_snark},
        load_block_traces_for_test, PARAMS_DIR,
    },
    utils::{chunk_trace_to_witness_block, init_env_and_log, load_or_download_params},
    zkevm::circuit::AGG_DEGREE,
};
use std::{env::set_var, path::Path};

#[cfg(feature = "prove_verify")]
#[test]
fn test_agg_prove_verify() {
    // Init, load block traces, construct prover and verifier.

    let output_dir = init_env_and_log("agg_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    set_var("TRACE_PATH", "./tests/traces/erc20/1_transfer.json");
    let chunk_trace1 = load_block_traces_for_test().1;
    set_var("TRACE_PATH", "./tests/traces/erc20/10_transfer.json");
    let chunk_trace2 = load_block_traces_for_test().1;
    log::info!("Loaded chunk-traces");

    let params = load_or_download_params(PARAMS_DIR, *AGG_DEGREE).unwrap();
    let mut prover = Prover::from_params(*AGG_DEGREE, params.clone());
    let verifier = Verifier::from_params(params);
    log::info!("Constructed prover and verifier");

    // gupeng

    // Convert chunk trace to witness block.
    let witness_block = chunk_trace_to_witness_block(chunk_trace1).unwrap();

    // Load or generate chunk snark.
    let chunk_snark = load_or_gen_chunk_snark(&output_dir, &mut prover, witness_block);
    log::info!("Got chunk snark");

    // Load or generate compression wide snark (layer-1).
    let layer1_snark =
        load_or_gen_comp_snark(&output_dir, "comp_wide", true, 22, &mut prover, chunk_snark);
    log::info!("Got compression wide snark (layer-1)");

    // Load or generate compression thin snark (layer-2).
    let layer2_snark = load_or_gen_comp_snark(
        &output_dir,
        "comp_thin",
        false,
        *AGG_DEGREE,
        &mut prover,
        layer1_snark,
    );
    log::info!("Got compression thin snark (layer-2)");

    /*
    // Load or generate aggregation snark (layer-3).
    let layer3_snark = load_or_gen_agg_snark(&output_dir, "agg", &mut prover, layer2_snark);
    log::info!("Got aggregation snark (layer-3)");

    // Load or generate compression EVM proof (layer-4).
    let proof = load_or_gen_comp_evm_proof(
        &output_dir,
        "comp_thin",
        false,
        *AGG_DEGREE,
        &mut prover,
        layer3_snark,
    );
    log::info!("Got compression EVM proof (layer-4)");

    // Verify the proof.
    let yul_file_path = format!("{output_dir}/agg_verifier.yul");
    verifier.evm_verify::<CompressionCircuit>(&proof, Some(Path::new(&yul_file_path)));
    */
}

/*

fn test_e2e() {

    // layer 3 proof aggregation
    std::env::set_var("VERIFY_CONFIG", "./configs/aggregation.config");
    let layer_3_snark = aggregation_layer_snark!(layer_2_snarks, params, k3, path, 3, chunks);

*/
