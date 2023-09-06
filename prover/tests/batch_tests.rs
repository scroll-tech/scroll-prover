use prover::{
    aggregator::Prover,
    proof::from_json_file,
    test_util::{gen_and_verify_batch_proofs, PARAMS_DIR},
    utils::init_env_and_log,
    ChunkHash, ChunkProof,
};
use serde_derive::{Deserialize, Serialize};
use std::env;

#[cfg(feature = "prove_verify")]
#[test]
fn test_batch_prove_verify() {
    env::set_var("KECCAK_ROW", 50);

    let output_dir = init_env_and_log("batch_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_hashes_proofs = load_chunk_hashes_and_proofs("tests/test_data", "1");
    log::info!("Loaded chunk-hashes and chunk-proofs");

    chunk_hashes_proofs
        .first()
        .unwrap()
        .1
        .dump(&output_dir, "0")
        .unwrap();

    env::set_var("AGG_VK_FILENAME", "vk_batch_agg.vkey");
    env::set_var("CHUNK_PROTOCOL_FILENAME", "chunk_chunk_0.protocol");
    let mut agg_prover = Prover::from_dirs(PARAMS_DIR, &output_dir);
    log::info!("Constructed aggregation prover");

    // Load or generate aggregation snark (layer-3).
    let layer3_snark = agg_prover
        .load_or_gen_last_agg_snark("agg", chunk_hashes_proofs, Some(&output_dir))
        .unwrap();

    gen_and_verify_batch_proofs(&mut agg_prover, layer3_snark, &output_dir);
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchTaskDetail {
    chunk_infos: Vec<ChunkHash>,
    chunk_proofs: Vec<ChunkProof>,
}

fn load_chunk_hashes_and_proofs(dir: &str, filename: &str) -> Vec<(ChunkHash, ChunkProof)> {
    let batch_task_detail: BatchTaskDetail = from_json_file(dir, filename).unwrap();
    let chunk_hashes = batch_task_detail.chunk_infos;
    let chunk_proofs = batch_task_detail.chunk_proofs;

    chunk_hashes[..]
        .to_vec()
        .into_iter()
        .zip(chunk_proofs[..].to_vec().into_iter())
        .collect()
}
