use crate::utils::{c_char_to_str, c_char_to_vec, vec_to_c_char};
use libc::c_char;
use prover::{aggregator, config::ALL_AGG_DEGREES, utils::init_env_and_log, zkevm};
use std::cell::OnceCell;
use types::eth::BlockTrace;

static mut CHUNK_PROVER: OnceCell<zkevm::Prover> = OnceCell::new();
static mut AGG_PROVER: OnceCell<aggregator::Prover> = OnceCell::new();
static mut AGG_CHUNK_TRACES: OnceCell<Vec<Vec<BlockTrace>>> = OnceCell::new();

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn init_chunk_prover(params_dir: *const c_char) {
    init_env_and_log("ffi_chunk_prove");

    let params_dir = c_char_to_str(params_dir);
    let prover = zkevm::Prover::from_params_dir(params_dir);
    CHUNK_PROVER.set(prover).unwrap();
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn init_agg_prover(params_dir: *const c_char) {
    init_env_and_log("ffi_agg_prove");

    let params_dir = c_char_to_str(params_dir);

    let prover = aggregator::Prover::from_params_dir(params_dir, &ALL_AGG_DEGREES);
    AGG_PROVER.set(prover).unwrap();
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_block_proof(trace_char: *const c_char) -> *const c_char {
    let trace_vec = c_char_to_vec(trace_char);
    let trace = serde_json::from_slice::<_>(&trace_vec).unwrap();
    let proof = CHUNK_PROVER
        .get_mut()
        .unwrap()
        .gen_chunk_proof(&[trace])
        .unwrap();
    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_chunk_proof(trace_char: *const c_char) -> *const c_char {
    let trace_vec = c_char_to_vec(trace_char);
    let traces = serde_json::from_slice::<Vec<_>>(&trace_vec).unwrap();
    let proof = CHUNK_PROVER
        .get_mut()
        .unwrap()
        .gen_chunk_proof(traces.as_slice())
        .unwrap();
    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn add_agg_chunk_trace(trace_char: *const c_char) {
    let trace_vec = c_char_to_vec(trace_char);
    let trace = serde_json::from_slice::<Vec<_>>(&trace_vec).unwrap();

    AGG_CHUNK_TRACES
        .get_mut()
        .or_else(|| {
            AGG_CHUNK_TRACES.set(vec![]).unwrap();
            AGG_CHUNK_TRACES.get_mut()
        })
        .unwrap()
        .push(trace);
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn clear_agg_chunk_traces() {
    if let Some(chunk_traces) = AGG_CHUNK_TRACES.get_mut() {
        chunk_traces.clear();
    }
}

// TODO: add a function `create_agg_proof`.
