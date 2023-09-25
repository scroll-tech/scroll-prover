use integration::test_util::{
    gen_and_verify_batch_proofs, load_block_traces_for_test, ASSETS_DIR, PARAMS_DIR,
};
use prover::{
    aggregator::Prover,
    utils::{chunk_trace_to_witness_block, init_env_and_log},
    zkevm, ChunkHash, ChunkProof,
};
use std::{env, fs, path::PathBuf};

#[cfg(feature = "prove_verify")]
#[test]
fn test_agg_prove_verify() {
    let output_dir = init_env_and_log("agg_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let trace_paths = vec!["./tests/extra_traces/new.json".to_string()];
    let chunk_hashes_proofs = gen_chunk_hashes_and_proofs(&output_dir, &trace_paths);

    let mut batch_prover = new_batch_prover(&output_dir);
    batch_prove_and_verify(&output_dir, &mut batch_prover, chunk_hashes_proofs);
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_recursive_prove_verify() {
    let output_dir = init_env_and_log("recursive_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    // Get chunk paths in a batch dir.
    let batch_path = env::var("BATCH_PATH").unwrap();
    let mut chunk_paths: Vec<_> = fs::read_dir(&batch_path)
        .unwrap()
        .into_iter()
        .map(|entry| entry.unwrap().path().to_string_lossy().to_string())
        .collect();
    chunk_paths.sort();
    log::info!("Get chunks in {batch_path}: {chunk_paths:?}");

    let chunk_hashes_proofs = gen_chunk_hashes_and_proofs(&output_dir, &chunk_paths);
    let mut batch_prover = new_batch_prover(&output_dir);

    // Iterate over chunk proofs to test with 1 - 15 chunks (in a batch).
    for i in 0..chunk_hashes_proofs.len() {
        let mut output_dir = PathBuf::from(&output_dir);
        output_dir.push(format!("batch_{}", i + 1));
        fs::create_dir_all(&output_dir).unwrap();

        batch_prove_and_verify(
            &output_dir.to_string_lossy().to_string(),
            &mut batch_prover,
            chunk_hashes_proofs[..=i].to_vec(),
        );
    }
}

fn batch_prove_and_verify(
    output_dir: &str,
    batch_prover: &mut Prover,
    chunk_hashes_proofs: Vec<(ChunkHash, ChunkProof)>,
) {
    // Load or generate aggregation snark (layer-3).
    let layer3_snark = batch_prover
        .load_or_gen_last_agg_snark("agg", chunk_hashes_proofs, Some(&output_dir))
        .unwrap();

    gen_and_verify_batch_proofs(batch_prover, layer3_snark, &output_dir);
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

    let chunk_hashes_proofs = chunk_traces
        .into_iter()
        .enumerate()
        .map(|(i, chunk_trace)| {
            let witness_block = chunk_trace_to_witness_block(chunk_trace.clone()).unwrap();
            let chunk_hash = ChunkHash::from_witness_block(&witness_block, false);

            let proof = zkevm_prover
                .gen_chunk_proof(chunk_trace, Some(&i.to_string()), None, Some(output_dir))
                .unwrap();

            (chunk_hash, proof)
        })
        .collect();

    log::info!("Generated chunk hashes and proofs");
    chunk_hashes_proofs
}

fn new_batch_prover(assets_dir: &str) -> Prover {
    env::set_var("AGG_VK_FILENAME", "vk_batch_agg.vkey");
    env::set_var("CHUNK_PROTOCOL_FILENAME", "chunk_chunk_0.protocol");
    let prover = Prover::from_dirs(PARAMS_DIR, &assets_dir);
    log::info!("Constructed batch prover");

    prover
}
