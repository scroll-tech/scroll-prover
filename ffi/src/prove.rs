use crate::utils::{c_char_to_str, c_char_to_vec, vec_to_c_char};
use libc::c_char;
use once_cell::sync::Lazy;
use prover::{
    aggregator::{self, ChunkHash},
    config::AGG_DEGREES,
    utils::init_env_and_log,
    zkevm, Proof,
};
use std::{cell::OnceCell, env};
use types::eth::BlockTrace;

static mut ZKEVM_PROVER: OnceCell<zkevm::Prover> = OnceCell::new();
static mut AGG_PROVER: OnceCell<aggregator::Prover> = OnceCell::new();

// Only used for debugging.
static OUTPUT_DIR: Lazy<Option<String>> = Lazy::new(|| env::var("PROVER_OUTPUT_DIR").ok());

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn init_zkevm_prover(params_dir: *const c_char) {
    init_env_and_log("ffi_zkevm_prove");

    let params_dir = c_char_to_str(params_dir);
    let prover = zkevm::Prover::from_params_dir(params_dir);
    ZKEVM_PROVER.set(prover).unwrap();
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn init_agg_prover(params_dir: *const c_char) {
    init_env_and_log("ffi_agg_prove");

    let params_dir = c_char_to_str(params_dir);

    let prover = aggregator::Prover::from_params_dir(params_dir, &AGG_DEGREES);
    AGG_PROVER.set(prover).unwrap();
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_block_proof(block_trace: *const c_char) -> *const c_char {
    let block_trace = c_char_to_vec(block_trace);
    let block_trace = serde_json::from_slice::<BlockTrace>(&block_trace).unwrap();

    let proof = ZKEVM_PROVER
        .get_mut()
        .unwrap()
        .gen_chunk_proof(&[block_trace])
        .unwrap();

    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_chunk_proof(block_traces: *const c_char) -> *const c_char {
    let block_traces = c_char_to_vec(block_traces);
    let block_traces = serde_json::from_slice::<Vec<BlockTrace>>(&block_traces).unwrap();

    let proof = ZKEVM_PROVER
        .get_mut()
        .unwrap()
        .gen_chunk_proof(block_traces.as_slice())
        .unwrap();

    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_agg_proof(
    chunk_hashes: *const c_char,
    chunk_proofs: *const c_char,
) -> *const c_char {
    let chunk_hashes = c_char_to_vec(chunk_hashes);
    let chunk_proofs = c_char_to_vec(chunk_proofs);

    let chunk_hashes = serde_json::from_slice::<Vec<ChunkHash>>(&chunk_hashes).unwrap();
    let chunk_proofs = serde_json::from_slice::<Vec<Proof>>(&chunk_proofs).unwrap();
    assert_eq!(chunk_hashes.len(), chunk_proofs.len());

    let chunks = chunk_hashes
        .into_iter()
        .zip(chunk_proofs.into_iter())
        .collect();

    let proof = AGG_PROVER
        .get_mut()
        .unwrap()
        .gen_agg_proof(chunks, OUTPUT_DIR.as_deref())
        .unwrap();

    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}
