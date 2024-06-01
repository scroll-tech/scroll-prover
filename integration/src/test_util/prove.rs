use super::PARAMS_DIR;
use prover::{
    aggregator::{Prover, Verifier},
    BatchProvingTask,
};
use std::env;

/// The `output_dir` is assumed to output_dir of chunk proving.
pub fn new_batch_prover(output_dir: &str) -> Prover {
    env::set_var("CHUNK_PROTOCOL_FILENAME", "chunk_chunk_0.protocol");
    let prover = Prover::from_dirs(PARAMS_DIR, output_dir);
    log::info!("Constructed batch prover");

    prover
}

pub fn prove_and_verify_batch(
    output_dir: &str,
    batch_prover: &mut Prover,
    batch: BatchProvingTask,
) {
    let chunk_num = batch.chunk_proofs.len();
    log::info!("Prove batch BEGIN: chunk_num = {chunk_num}");

    let batch_proof = batch_prover
        .gen_agg_evm_proof(batch, None, Some(output_dir))
        .unwrap();

    env::set_var("AGG_VK_FILENAME", "vk_batch_agg.vkey");
    let verifier = Verifier::from_dirs(PARAMS_DIR, output_dir);
    log::info!("Constructed aggregator verifier");

    assert!(verifier.verify_agg_evm_proof(batch_proof));
    log::info!("Verified batch proof");

    log::info!("Prove batch END: chunk_num = {chunk_num}");
}
