use crate::utils::{c_char_to_str, vec_to_c_char};
use libc::c_char;
use once_cell::sync::Lazy;
use types::eth::BlockResult;
use zkevm::circuit::{EvmCircuit, StateCircuit, AGG_DEGREE};
use zkevm::utils::{load_or_create_params, load_or_create_seed, read_env_var};
use zkevm::{circuit::DEGREE, prover::Prover};

static mut PROVER: Lazy<Prover> = Lazy::new(|| {
    let params_path = read_env_var("params_path", "/tmp/params".to_string());
    let seed_path = read_env_var("seed_path", "/tmp/seed".to_string());
    let params = load_or_create_params(&params_path, *DEGREE).unwrap();
    let agg_params = load_or_create_params(&params_path, *AGG_DEGREE).unwrap();
    let seed = load_or_create_seed(&seed_path).unwrap();
    Prover::from_params_and_seed(params, agg_params, seed)
});

/// # Safety
pub unsafe extern "C" fn create_agg_proof(trace_char: *const c_char) -> *const c_char {
    let trace_str = c_char_to_str(trace_char);
    let trace = serde_json::from_str::<BlockResult>(trace_str).unwrap();
    let proof = PROVER.create_agg_circuit_proof(&trace).unwrap();
    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_evm_proof(trace_char: *const c_char) -> *const c_char {
    let trace_str = c_char_to_str(trace_char);
    let trace = serde_json::from_str::<BlockResult>(trace_str).unwrap();
    let proof = PROVER
        .create_target_circuit_proof::<EvmCircuit>(&trace)
        .unwrap();
    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_state_proof(trace_char: *const c_char) -> *const c_char {
    let trace_str = c_char_to_str(trace_char);
    let trace = serde_json::from_str::<BlockResult>(trace_str).unwrap();
    let proof = PROVER
        .create_target_circuit_proof::<StateCircuit>(&trace)
        .unwrap();
    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}
