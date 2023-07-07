use aggregator::CompressionCircuit;
use prover::{
    aggregator::{Prover, Verifier},
    config::{
        AGG_LAYER1_DEGREE, AGG_LAYER2_DEGREE, AGG_LAYER3_DEGREE, AGG_LAYER4_DEGREE, ALL_AGG_DEGREES,
    },
    test_util::{
        aggregator::{
            gen_comp_evm_proof, load_or_gen_agg_snark, load_or_gen_chunk_snark,
            load_or_gen_comp_snark,
        },
        load_block_traces_for_test, PARAMS_DIR,
    },
    utils::{chunk_trace_to_witness_block, init_env_and_log},
};
use std::{env::set_var, path::Path};

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
    let chunk_hashes: Vec<_> = witness_blocks.iter().map(Into::into).collect();
    log::info!("Got chunk-hashes");

    let mut prover = Prover::from_params_dir(PARAMS_DIR, &*ALL_AGG_DEGREES);
    log::info!("Constructed prover");

    // Load or generate chunk snarks.
    let chunk_snarks: Vec<_> = witness_blocks
        .into_iter()
        .enumerate()
        .map(|(i, block)| load_or_gen_chunk_snark(&output_dir, &i.to_string(), &mut prover, block))
        .collect();
    log::info!("Got chunk-snarks");

    // Load or generate compression wide snarks (layer-1).
    let layer1_snarks: Vec<_> = chunk_snarks
        .into_iter()
        .map(|snark| {
            load_or_gen_comp_snark(
                &output_dir,
                "agg_layer1",
                true,
                *AGG_LAYER1_DEGREE,
                &mut prover,
                snark,
            )
        })
        .collect();
    log::info!("Got compression wide snarks (layer-1)");

    // Load or generate compression thin snarks (layer-2).
    let layer2_snarks: Vec<_> = layer1_snarks
        .into_iter()
        .map(|snark| {
            load_or_gen_comp_snark(
                &output_dir,
                "agg_layer2",
                false,
                *AGG_LAYER2_DEGREE,
                &mut prover,
                snark,
            )
        })
        .collect();
    log::info!("Got compression thin snarks (layer-2)");

    // Load or generate aggregation snark (layer-3).
    let layer3_snark = load_or_gen_agg_snark(
        &output_dir,
        "agg_layer3",
        *AGG_LAYER3_DEGREE,
        &mut prover,
        &chunk_hashes,
        &layer2_snarks,
    );
    log::info!("Got aggregation snark (layer-3)");

    // Load or generate compression EVM proof (layer-4).
    let proof = gen_comp_evm_proof(
        &output_dir,
        "agg_layer4",
        false,
        *AGG_LAYER4_DEGREE,
        &mut prover,
        layer3_snark,
    );
    log::info!("Got compression EVM proof (layer-4)");

    // Construct verifier and EVM verify.
    let params = prover.params(*AGG_LAYER4_DEGREE).clone();
    let vk = prover.pk("agg_layer4").unwrap().get_vk().clone();
    let verifier = Verifier::new(params, Some(vk));
    let yul_file_path = format!("{output_dir}/agg_verifier.yul");
    verifier.evm_verify::<CompressionCircuit>(&proof, Some(Path::new(&yul_file_path)));
    log::info!("Finish EVM verify");
}
