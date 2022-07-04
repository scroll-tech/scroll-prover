use crate::utils::{c_char_to_str, c_char_to_vec};
use libc::c_char;
use once_cell::sync::Lazy;
use types::eth::BlockResult;
use zkevm::circuit::DEGREE;
use zkevm::utils::{load_or_create_params, read_env_var};
use zkevm::verifier::Verifier;

static VERIFIER: Lazy<Verifier> = Lazy::new(|| {
    let params_path = read_env_var("params_path", "params".to_string());
    let params = load_or_create_params(&params_path, *DEGREE).unwrap();
    Verifier::from_params(params)
});

#[no_mangle]
pub unsafe extern "C" fn verify_evm_proof(
    trace_char: *const c_char,
    proof: *const c_char,
) -> *const c_char {
    let trace_str = c_char_to_str(trace_char);
    let trace = serde_json::from_str::<BlockResult>(trace_str).unwrap();
    let proof = c_char_to_vec(proof);
    let verified = VERIFIER.verify_evm_proof(proof, &trace);
    verified as *const c_char
}

#[no_mangle]
pub unsafe extern "C" fn verify_state_proof(
    trace_char: *const c_char,
    proof: *const c_char,
) -> *const c_char {
    let trace_str = c_char_to_str(trace_char);
    let trace = serde_json::from_str::<BlockResult>(trace_str).unwrap();
    let proof = c_char_to_vec(proof);
    let verified = VERIFIER.verify_state_proof(proof, &trace);
    verified as *const c_char
}
