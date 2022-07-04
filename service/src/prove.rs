use crate::utils::{c_char_to_str, vec_to_c_char};
use std::os::raw::c_char;
use std::sync::Arc;
use once_cell::sync::Lazy;
use types::eth::BlockResult;
use zkevm::utils::{load_or_create_params, load_or_create_seed};
use zkevm::{circuit::DEGREE, prover::Prover};

static mut PROVER: Lazy<Prover> = Lazy::new();

#[no_mangle]
pub unsafe extern "C" fn init_prover(params_path: *const c_char, seed_path: *const c_char) {
    let params_fpath = c_char_to_str(params_path);
    let seed_fpath = c_char_to_str(seed_path);

    let params = load_or_create_params(params_fpath, *DEGREE).unwrap();
    let seed = load_or_create_seed(seed_fpath).unwrap();

    PROVER.get_or_insert_with(|| Arc::new({ Prover::from_params_and_seed(params, seed) }).clone());
}

#[no_mangle]
pub unsafe extern "C" fn create_evm_proof(trace_char: *const c_char) -> *const c_char {
    let trace_str = c_char_to_str(trace_char);
    let trace = serde_json::from_str::<BlockResult>(trace_str).unwrap();
    let proof = PROVER.unwrap().create_evm_proof(&trace).unwrap();
    vec_to_c_char(proof)
}

#[no_mangle]
pub unsafe extern "C" fn create_state_proof(trace_char: *const c_char) -> *const c_char {
    let trace_str = c_char_to_str(trace_char);
    let trace = serde_json::from_str::<BlockResult>(trace_str).unwrap();
    let proof = PROVER.unwrap().create_state_proof(&trace).unwrap();
    vec_to_c_char(proof)
}
