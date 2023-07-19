use aggregator::{CompressionCircuit, MAX_AGG_SNARKS};
use prover::{
    common::{Prover, Verifier},
    config::{AGG_DEGREES, LAYER1_DEGREE, LAYER2_DEGREE, LAYER3_DEGREE, LAYER4_DEGREE},
    test_util::{load_block_traces_for_test, PARAMS_DIR},
    utils::{chunk_trace_to_witness_block, init_env_and_log},
};
use std::{env::set_var, iter::repeat};

#[cfg(feature = "prove_verify")]
#[test]
fn test_agg_prove_verify() {
    // Init, load block traces and construct prover.

    let output_dir = init_env_and_log("agg_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let mut chunk_traces = vec![];
    set_var("TRACE_PATH", "./tests/traces/erc20/1_transfer.json");
    chunk_traces.push(load_block_traces_for_test().1);
    set_var("TRACE_PATH", "./tests/traces/erc20/10_transfer.json");
    chunk_traces.push(load_block_traces_for_test().1);
    log::info!("Loaded chunk-traces");

    // Convert chunk traces to witness blocks.
    let witness_blocks: Vec<_> = chunk_traces
        .into_iter()
        .map(|trace| chunk_trace_to_witness_block(trace).unwrap())
        .collect();
    log::info!("Got witness-blocks");

    // Convert witness blocks to chunk hashes.
    let real_chunk_hashes: Vec<_> = witness_blocks.iter().map(Into::into).collect();
    log::info!("Got real-chunk-hashes");

    let mut prover = Prover::from_params_dir(PARAMS_DIR, &*AGG_DEGREES);
    log::info!("Constructed prover");

    // Load or generate real inner snarks.
    let inner_snarks: Vec<_> = witness_blocks
        .into_iter()
        .enumerate()
        .map(|(i, witness_block)| {
            prover
                .load_or_gen_inner_snark(&format!("layer0_{i}"), witness_block, Some(&output_dir))
                .unwrap()
        })
        .collect();
    log::info!("Got real-inner-snarks");

    // Load or generate compression wide snarks (layer-1).
    let mut layer1_snarks: Vec<_> = inner_snarks
        .into_iter()
        .enumerate()
        .map(|(i, snark)| {
            prover
                .load_or_gen_comp_snark(
                    &format!("layer1_{i}"),
                    "layer1",
                    true,
                    *LAYER1_DEGREE,
                    snark,
                    Some(&output_dir),
                )
                .unwrap()
        })
        .collect();
    log::info!("Got compression-wide-snarks (layer-1)");

    // Load or generate layer-1 padding snark.
    let layer1_padding_snark = prover
        .load_or_gen_padding_snark(
            "layer1",
            *LAYER1_DEGREE,
            real_chunk_hashes.last().unwrap(),
            Some(&output_dir),
        )
        .unwrap();
    layer1_snarks.push(layer1_padding_snark);
    log::info!("Got layer1-padding-snark");

    // Load or generate compression thin snarks (layer-2).
    let mut layer2_snarks: Vec<_> = layer1_snarks
        .into_iter()
        .enumerate()
        .map(|(i, snark)| {
            prover
                .load_or_gen_comp_snark(
                    &format!("layer2_{i}"),
                    "layer2",
                    false,
                    *LAYER2_DEGREE,
                    snark,
                    Some(&output_dir),
                )
                .unwrap()
        })
        .collect();
    log::info!("Got compression-thin-snarks (layer-2)");

    // Extend to MAX_AGG_SNARKS by copying the last padding snark.
    layer2_snarks.extend(
        repeat(layer2_snarks.last().unwrap().clone()).take(MAX_AGG_SNARKS - layer2_snarks.len()),
    );

    // Load or generate aggregation snark (layer-3).
    let layer3_snark = prover
        .load_or_gen_agg_snark(
            "layer3_0",
            "layer3",
            *LAYER3_DEGREE,
            &real_chunk_hashes,
            &layer2_snarks,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got aggregation-snark (layer-3)");

    // Load or generate compression EVM proof (layer-4).
    let proof = prover
        .gen_comp_evm_proof(
            "layer4_0",
            "layer4",
            false,
            *LAYER4_DEGREE,
            layer3_snark,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression-EVM-proof (layer-4)");

    // Construct verifier and EVM verify.
    let params = prover.params(*LAYER4_DEGREE).clone();
    let vk = proof.vk::<CompressionCircuit>();
    let verifier = Verifier::new(params, vk);
    verifier.evm_verify::<CompressionCircuit>(&proof, &output_dir);
    log::info!("Finish EVM verify");
}
