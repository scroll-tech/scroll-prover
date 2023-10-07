use integration::test_util::{gen_and_verify_batch_proofs, PARAMS_DIR};
use prover::{
    aggregator::Prover, proof::from_json_file, utils::init_env_and_log, ChunkHash, ChunkProof,
};
use serde_derive::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf};

#[cfg(feature = "prove_verify")]
#[test]
fn test_batch_prove_verify() {
    let output_dir = init_env_and_log("batch_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_hashes_proofs = load_chunk_hashes_and_proofs("tests/test_data", "1", &output_dir);
    let mut batch_prover = new_batch_prover(&output_dir);
    prove_and_verify_batch(&output_dir, &mut batch_prover, chunk_hashes_proofs);
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_batches_with_each_chunk_num_prove_verify() {
    let output_dir = init_env_and_log("batches_with_each_chunk_num_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_hashes_proofs = load_chunk_hashes_and_proofs("tests/test_data", "2", &output_dir);
    let mut batch_prover = new_batch_prover(&output_dir);

    // Iterate over chunk proofs to test with 1 - 15 chunks (in a batch).
    for i in 0..chunk_hashes_proofs.len() {
        let mut output_dir = PathBuf::from(&output_dir);
        output_dir.push(format!("batch_{}", i + 1));
        fs::create_dir_all(&output_dir).unwrap();

        prove_and_verify_batch(
            &output_dir.to_string_lossy(),
            &mut batch_prover,
            chunk_hashes_proofs[..=i].to_vec(),
        );
    }
}
#[derive(Debug, Deserialize, Serialize)]
struct BatchTaskDetail {
    chunk_infos: Vec<ChunkHash>,
    chunk_proofs: Vec<ChunkProof>,
}

fn load_chunk_hashes_and_proofs(
    dir: &str,
    filename: &str,
    output_dir: &str,
) -> Vec<(ChunkHash, ChunkProof)> {
    let batch_task_detail: BatchTaskDetail = from_json_file(dir, filename).unwrap();
    let chunk_hashes = batch_task_detail.chunk_infos;
    let chunk_proofs = batch_task_detail.chunk_proofs;

    let chunk_hashes_proofs: Vec<_> = chunk_hashes[..]
        .iter()
        .copied()
        .zip(chunk_proofs[..].iter().cloned())
        .collect();

    // Dump chunk-procotol for further batch-proving.
    chunk_hashes_proofs
        .first()
        .unwrap()
        .1
        .dump(output_dir, "0")
        .unwrap();

    log::info!(
        "Loaded chunk-hashes and chunk-proofs: total = {}",
        chunk_hashes_proofs.len()
    );
    chunk_hashes_proofs
}

fn new_batch_prover(assets_dir: &str) -> Prover {
    env::set_var("AGG_VK_FILENAME", "vk_batch_agg.vkey");
    env::set_var("CHUNK_PROTOCOL_FILENAME", "chunk_chunk_0.protocol");
    let prover = Prover::from_dirs(PARAMS_DIR, assets_dir);
    log::info!("Constructed batch prover");

    prover
}

fn prove_and_verify_batch(
    output_dir: &str,
    batch_prover: &mut Prover,
    chunk_hashes_proofs: Vec<(ChunkHash, ChunkProof)>,
) {
    let chunk_num = chunk_hashes_proofs.len();
    log::info!("Prove batch BEGIN: chunk_num = {chunk_num}");

    // Load or generate aggregation snark (layer-3).
    let layer3_snark = batch_prover
        .load_or_gen_last_agg_snark("agg", chunk_hashes_proofs, Some(output_dir))
        .unwrap();

    gen_and_verify_batch_proofs(batch_prover, layer3_snark, output_dir);

    log::info!("Prove batch END: chunk_num = {chunk_num}");
}
