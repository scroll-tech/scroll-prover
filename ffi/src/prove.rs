use crate::utils::{c_char_to_str, c_char_to_vec, vec_to_c_char};
use libc::c_char;
use prover::utils::init_env_and_log;
use prover::zkevm;
use std::{cell::OnceCell, path::Path};
use types::eth::BlockTrace;

static mut PROVER: OnceCell<zkevm::Prover> = OnceCell::new();

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn init_prover(params_path: *const c_char, _seed_path: *const c_char) {
    init_env_and_log("ffi_prove");

    let params_path = c_char_to_str(params_path);
    let p = zkevm::Prover::from_param_dir(params_path);
    PROVER.set(p).unwrap();
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_block_proof(
    trace_char: *const c_char,
    pk_path: *const c_char,
) -> *const c_char {
    let trace_vec = c_char_to_vec(trace_char);
    let trace = serde_json::from_slice::<BlockTrace>(&trace_vec).unwrap();
    // Arg `pk_path` could be NULL.
    let pk_path = pk_path.as_ref().map(|p| Path::new(c_char_to_str(p)));
    let proof = PROVER
        .get_mut()
        .unwrap()
        .gen_chunk_proof(&[trace], pk_path)
        .unwrap();
    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_chunk_proof(
    trace_char: *const c_char,
    pk_path: *const c_char,
) -> *const c_char {
    let trace_vec = c_char_to_vec(trace_char);
    let traces = serde_json::from_slice::<Vec<BlockTrace>>(&trace_vec).unwrap();
    // Arg `pk_path` could be NULL.
    let pk_path = pk_path.as_ref().map(|p| Path::new(c_char_to_str(p)));
    let proof = PROVER
        .get_mut()
        .unwrap()
        .gen_chunk_proof(traces.as_slice(), pk_path)
        .unwrap();
    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}
