use prover::{
    aggregator::Prover,
    test_util::{gen_and_verify_batch_proofs, load_block_traces_for_test, ASSETS_DIR, PARAMS_DIR},
    utils::{chunk_trace_to_witness_block, init_env_and_log},
    zkevm, ChunkHash, ChunkProof,
};
use std::env;

#[cfg(feature = "prove_verify")]
#[test]
fn test_agg_prove_verify() {
    let output_dir = init_env_and_log("agg_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let trace_paths = vec!["./tests/extra_traces/new.json".to_string()];

    let chunk_hashes_proofs = gen_chunk_hashes_and_proofs(&output_dir, &trace_paths);
    log::info!("Generated chunk hashes and proofs");

    env::set_var("CHUNK_PROTOCOL_FILENAME", "chunk_chunk_0.protocol");
    let mut agg_prover = Prover::from_dirs(PARAMS_DIR, &output_dir);
    log::info!("Constructed aggregation prover");

    // Load or generate aggregation snark (layer-3).
    let layer3_snark = agg_prover
        .load_or_gen_last_agg_snark("agg", chunk_hashes_proofs, Some(&output_dir))
        .unwrap();

    gen_and_verify_batch_proofs(&mut agg_prover, layer3_snark, &output_dir);
}

fn gen_chunk_hashes_and_proofs(
    output_dir: &str,
    trace_paths: &[String],
) -> Vec<(ChunkHash, ChunkProof)> {
    let mut zkevm_prover = zkevm::Prover::from_dirs(PARAMS_DIR, ASSETS_DIR);
    log::info!("Constructed zkevm prover");

    let chunk_traces: Vec<_> = trace_paths
        .iter()
        .map(|trace_path| {
            env::set_var("TRACE_PATH", trace_path);
            load_block_traces_for_test().1
        })
        .collect();

    chunk_traces
        .into_iter()
        .enumerate()
        .map(|(i, chunk_trace)| {
            let witness_block = chunk_trace_to_witness_block(chunk_trace.clone()).unwrap();
            let chunk_hash = ChunkHash::from_witness_block(&witness_block, false);

            let proof = zkevm_prover
                .gen_chunk_proof(chunk_trace, Some(&i.to_string()), Some(output_dir))
                .unwrap();

            (chunk_hash, proof)
        })
        .collect()
}
