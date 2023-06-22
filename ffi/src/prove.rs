use crate::utils::{c_char_to_str, c_char_to_vec, vec_to_c_char};
use libc::c_char;
use prover::zkevm;
use prover::utils::init_env_and_log;
use std::cell::OnceCell;
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
pub unsafe extern "C" fn create_agg_proof(trace_char: *const c_char) -> *const c_char {
    let trace_vec = c_char_to_vec(trace_char);
    let trace = serde_json::from_slice::<BlockTrace>(&trace_vec).unwrap();
    let proof = PROVER
        .get_mut()
        .unwrap()
        .create_agg_circuit_proof(&trace)
        .unwrap();
    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_agg_proof_multi(trace_char: *const c_char) -> *const c_char {
    let trace_vec = c_char_to_vec(trace_char);
    let traces = serde_json::from_slice::<Vec<BlockTrace>>(&trace_vec).unwrap();
    let proof = PROVER
        .get_mut()
        .unwrap()
        .create_agg_circuit_proof_batch(traces.as_slice())
        .unwrap();
    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}
