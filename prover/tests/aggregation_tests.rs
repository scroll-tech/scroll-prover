use prover::{
    aggregator::{Prover, Verifier},
    test_util::{
        aggregator::{load_or_gen_chunk_snark, load_or_gen_comp_snark},
        load_block_traces_for_test, PARAMS_DIR,
    },
    utils::{chunk_trace_to_witness_block, init_env_and_log, load_or_download_params},
    zkevm::circuit::AGG_DEGREE,
};

#[cfg(feature = "prove_verify")]
#[test]
fn test_agg_prove_verify() {
    // . Init, load block traces, construct prover and verifier.

    let output_dir = init_env_and_log("agg_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    // gupeng

    let chunk_trace = load_block_traces_for_test().1;
    log::info!("Loaded chunk-trace");

    let params = load_or_download_params(PARAMS_DIR, *AGG_DEGREE).unwrap();
    let mut prover = Prover::from_params(params.clone());
    let verifier = Verifier::from_params(params);
    log::info!("Constructed prover and verifier");

    // Convert chunk trace to witness block.
    let witness_block = chunk_trace_to_witness_block(chunk_trace).unwrap();

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
    // 5. Load or generate aggregation snark (layer-3).
    let layer3_snark = load_or_gen_agg_snark(&output_dir, "agg", &mut prover, layer2_snark);
    log::info!("Got aggregation snark (layer-3)");




    // gupeng
    // 4. Load or generate compression EVM proof (layer-2).
    let proof = load_or_gen_comp_evm_proof(
        &output_dir,
        "comp_thin",
        false,
        &mut prover,
        comp_wide_snark,
    );
    log::info!("Got compression EVM proof (layer-2)");

    // 5. Verify the proof.
    let yul_file_path = format!("{output_dir}/agg_verifier.yul");
    verifier.evm_verify::<CompressionCircuit>(&proof, Some(Path::new(&yul_file_path)));

    */
}

/*

const CHUNKS_PER_BATCH: usize = 2;

// This test takes about 1 hour on CPU
#[ignore = "it takes too much time"]
#[test]
fn test_e2e() {

    // inner circuit: Mock circuit
    let k0 = 8;
    // wide compression
    let k1 = 21;
    // thin compression
    let k2 = 26;
    // aggregation
    let k3 = 26;
    // thin compression
    let k4 = 26;

    let mut chunks = (0..CHUNKS_PER_BATCH)
        .map(|_| ChunkHash::mock_chunk_hash(&mut rng))
        .collect_vec();
    for i in 0..CHUNKS_PER_BATCH - 1 {
        chunks[i + 1].prev_state_root = chunks[i].post_state_root;
    }

    // Proof for test circuit
    let circuits = chunks
        .iter()
        .map(|&chunk| MockChunkCircuit {
            is_fresh: true,
            chain_id: 0,
            chunk,
        })
        .collect_vec();
    let layer_0_snarks = circuits
        .iter()
        .map(|&circuit| layer_0!(circuit, MockChunkCircuit, params, k0, path))
        .collect_vec();

    // Layer 1 proof compression
    std::env::set_var("VERIFY_CONFIG", "./configs/compression_wide.config");
    let layer_1_snarks = layer_0_snarks
        .iter()
        .map(|layer_0_snark| compression_layer_snark!(layer_0_snark, params, k1, path, 1))
        .collect_vec();

    // Layer 2 proof compression
    std::env::set_var("VERIFY_CONFIG", "./configs/compression_thin.config");
    let layer_2_snarks = layer_1_snarks
        .iter()
        .map(|layer_1_snark| compression_layer_snark!(layer_1_snark, params, k2, path, 2))
        .collect_vec();

    // layer 3 proof aggregation
    std::env::set_var("VERIFY_CONFIG", "./configs/aggregation.config");
    let layer_3_snark = aggregation_layer_snark!(layer_2_snarks, params, k3, path, 3, chunks);

    // layer 4 proof compression and final evm verification
    std::env::set_var("VERIFY_CONFIG", "./configs/compression_thin.config");
    compression_layer_evm!(layer_3_snark, params, k4, path, 4);
}

*/
