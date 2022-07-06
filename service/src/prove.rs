use crate::utils::{c_char_to_str, vec_to_c_char};
use libc::c_char;
use once_cell::sync::Lazy;
use types::eth::BlockResult;
use zkevm::utils::{load_or_create_params, load_or_create_seed, read_env_var};
use zkevm::{circuit::DEGREE, prover::Prover};

static mut PROVER: Lazy<Prover> = Lazy::new(|| {
    let params_path = read_env_var("params_path", "/tmp/params".to_string());
    let seed_path = read_env_var("seed_path", "/tmp/seed".to_string());
    let params = load_or_create_params(&params_path, *DEGREE).unwrap();
    let seed = load_or_create_seed(&seed_path).unwrap();
    Prover::from_params_and_seed(params, seed)
});

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_evm_proof(trace_char: *const c_char) -> *const c_char {
    let trace_str = c_char_to_str(trace_char);
    let trace = serde_json::from_str::<BlockResult>(trace_str).unwrap();
    let proof = PROVER.create_evm_proof(&trace).unwrap();
    vec_to_c_char(proof)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_state_proof(trace_char: *const c_char) -> *const c_char {
    let trace_str = c_char_to_str(trace_char);
    let trace = serde_json::from_str::<BlockResult>(trace_str).unwrap();
    let proof = PROVER.create_state_proof(&trace).unwrap();
    vec_to_c_char(proof)
}
