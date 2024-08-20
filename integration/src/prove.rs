use crate::{test_util::PARAMS_DIR, verifier::*};
use prover::{
    aggregator::Prover as BatchProver, zkevm::Prover as ChunkProver, BatchData, BatchProof,
    BatchProvingTask, BundleProvingTask, ChunkInfo, ChunkProvingTask, MAX_AGG_SNARKS,
};
use std::{env, time::Instant};

/// The `output_dir` is assumed to output_dir of chunk proving.
pub fn new_batch_prover(output_dir: &str) -> BatchProver {
    env::set_var("CHUNK_PROTOCOL_FILENAME", "chunk_chunk_0.protocol");
    let prover = BatchProver::from_dirs(PARAMS_DIR, output_dir);
    log::info!("Constructed batch prover");

    prover
}

pub fn prove_and_verify_chunk(
    chunk: ChunkProvingTask,
    chunk_identifier: Option<&str>,
    params_path: &str,
    assets_path: &str,
    output_dir: &str,
) {
    let mut prover = ChunkProver::from_dirs(params_path, assets_path);
    log::info!("Constructed chunk prover");

    let now = Instant::now();
    let chunk_proof = prover
        .gen_chunk_proof(chunk, chunk_identifier, None, Some(output_dir))
        .expect("cannot generate chunk snark");
    log::info!(
        "finish generating chunk snark, elapsed: {:?}",
        now.elapsed()
    );

    // output_dir is used to load chunk vk
    env::set_var("CHUNK_VK_FILENAME", "vk_chunk_0.vkey");
    let verifier = new_chunk_verifier(params_path, output_dir);
    assert!(verifier.verify_snark(chunk_proof.to_snark()));
    log::info!("Verified chunk proof");
}

pub fn prove_and_verify_batch(
    output_dir: &str,
    batch_prover: &mut BatchProver,
    batch: BatchProvingTask,
) -> BatchProof {
    let chunk_num = batch.chunk_proofs.len();
    log::info!("Prove batch BEGIN: chunk_num = {chunk_num}");

    let res_batch_proof = batch_prover.gen_batch_proof(batch, None, Some(output_dir));
    if let Err(e) = res_batch_proof {
        log::error!("proving err: {e}");
        panic!("proving err: {:?}", e);
    }
    let batch_proof = res_batch_proof.unwrap();

    env::set_var("BATCH_VK_FILENAME", "vk_batch_agg.vkey");
    let verifier = new_batch_verifier(PARAMS_DIR, output_dir);
    log::info!("Constructed aggregator verifier");

    assert!(verifier.verify_snark((&batch_proof).into()));
    log::info!("Verified batch proof");

    log::info!("Prove batch END: chunk_num = {chunk_num}");

    batch_proof
}

pub fn prove_and_verify_bundle(
    output_dir: &str,
    prover: &mut BatchProver,
    bundle: BundleProvingTask,
) {
    log::info!("Prove bundle BEGIN");

    let bundle_proof = prover
        .gen_bundle_proof(bundle, None, Some(output_dir))
        .unwrap();

    env::set_var("BATCH_VK_FILENAME", "vk_bundle_recursion.vkey");
    let verifier = EVMVerifier::from_dirs(output_dir);
    log::info!("Constructed bundle verifier");

    assert!(verifier.verify_evm_proof(bundle_proof.calldata()));
    log::info!("Verifier bundle proof");

    log::info!("Prove bundle END");
}

// `chunks` are unpadded
// Similar codes with aggregator/src/tests/aggregation.rs
// Refactor?
pub fn get_blob_from_chunks(chunks: &[ChunkInfo]) -> Vec<u8> {
    let num_chunks = chunks.len();

    let padded_chunk =
        ChunkInfo::mock_padded_chunk_info_for_testing(chunks.last().as_ref().unwrap());
    let chunks_with_padding = [
        chunks.to_vec(),
        vec![padded_chunk; MAX_AGG_SNARKS - num_chunks],
    ]
    .concat();
    let batch_data = BatchData::<{ MAX_AGG_SNARKS }>::new(chunks.len(), &chunks_with_padding);
    let batch_bytes = batch_data.get_batch_data_bytes();
    let blob_bytes = prover::aggregator::eip4844::get_blob_bytes(&batch_bytes);
    log::info!("blob_bytes len {}", blob_bytes.len());
    blob_bytes
}
