use aggregator::CompressionCircuit;
use prover::{
    aggregator::{Prover, Verifier},
    config::AGG_DEGREE,
    test_util::{
        aggregator::{
            load_or_gen_agg_snark, load_or_gen_chunk_snark, load_or_gen_comp_evm_proof,
            load_or_gen_comp_snark,
        },
        load_block_traces_for_test, PARAMS_DIR,
    },
    utils::{chunk_trace_to_witness_block, init_env_and_log, load_or_download_params},
};
use std::{env::set_var, path::Path};

#[cfg(feature = "prove_verify")]
#[test]
fn test_agg_prove_verify() {
    // Init, load chunk traces, construct prover and verifier.

    let output_dir = init_env_and_log("agg_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let mut chunk_traces = vec![];
    set_var("TRACE_PATH", "./tests/traces/erc20/1_transfer.json");
    chunk_traces.push(load_block_traces_for_test().1);
    set_var("TRACE_PATH", "./tests/traces/erc20/10_transfer.json");
    chunk_traces.push(load_block_traces_for_test().1);
    log::info!("Loaded chunk-traces");

    let params = load_or_download_params(PARAMS_DIR, *AGG_DEGREE).unwrap();
    let mut prover = Prover::from_params(*AGG_DEGREE, params.clone());
    let verifier = Verifier::from_params(params);
    log::info!("Constructed prover and verifier");

    // Convert chunk traces to witness blocks.
    let witness_blocks: Vec<_> = chunk_traces
        .into_iter()
        .map(|trace| chunk_trace_to_witness_block(trace).unwrap())
        .collect();

    // Convert witness blocks to chunk hashes.
    let chunk_hashes: Vec<_> = witness_blocks.iter().map(Into::into).collect();

    // Load or generate chunk snarks.
    let chunk_snarks: Vec<_> = witness_blocks
        .into_iter()
        .map(|block| load_or_gen_chunk_snark(&output_dir, &mut prover, block))
        .collect();
    log::info!("Got chunk-snarks");

    // Load or generate compression wide snarks (layer-1).
    let layer1_snarks: Vec<_> = chunk_snarks
        .into_iter()
        .map(|snark| load_or_gen_comp_snark(&output_dir, "comp_wide", true, 22, &mut prover, snark))
        .collect();
    log::info!("Got compression wide snarks (layer-1)");

    // Load or generate compression thin snarks (layer-2).
    let layer2_snarks: Vec<_> = layer1_snarks
        .into_iter()
        .map(|snark| {
            load_or_gen_comp_snark(
                &output_dir,
                "comp_thin",
                false,
                *AGG_DEGREE,
                &mut prover,
                snark,
            )
        })
        .collect();
    log::info!("Got compression thin snarks (layer-2)");

    // Load or generate aggregation snark (layer-3).
    let layer3_snark = load_or_gen_agg_snark(
        &output_dir,
        "agg",
        *AGG_DEGREE,
        &mut prover,
        &chunk_hashes,
        &layer2_snarks,
    );
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
}
