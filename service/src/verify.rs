use crate::utils::c_char_to_vec;
use libc::c_char;
use once_cell::sync::Lazy;
use std::fs::File;
use std::io::Read;
use zkevm::circuit::{EvmCircuit, StateCircuit, AGG_DEGREE, DEGREE};
use zkevm::prover::{AggCircuitProof, TargetCircuitProof};
use zkevm::utils::{load_or_create_params, read_env_var};
use zkevm::verifier::Verifier;

static VERIFIER: Lazy<Verifier> = Lazy::new(|| {
    let params_path = read_env_var("params_path", "/tmp/params".to_string());
    let agg_vk_path = read_env_var("agg_vk_path", "/tmp/agg_vk".to_string());
    let mut f = File::open(agg_vk_path).unwrap();
    let mut agg_vk = vec![];
    f.read_to_end(&mut agg_vk).unwrap();

    let params = load_or_create_params(&params_path, *DEGREE).unwrap();
    let agg_params = load_or_create_params(&params_path, *AGG_DEGREE).unwrap();

    Verifier::from_params(params, agg_params, Some(agg_vk))
});

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn verify_agg_proof(proof: *const c_char) -> c_char {
    let proof_vec = c_char_to_vec(proof);
    let agg_proof = serde_json::from_slice::<AggCircuitProof>(proof_vec.as_slice()).unwrap();
    let verified = VERIFIER.verify_agg_circuit_proof(agg_proof).is_ok();
    verified as c_char
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn verify_evm_proof(proof: *const c_char) -> c_char {
    let proof_vec = c_char_to_vec(proof);
    let proof = serde_json::from_slice::<TargetCircuitProof>(proof_vec.as_slice()).unwrap();
    let verified = VERIFIER
        .verify_target_circuit_proof::<EvmCircuit>(&proof)
        .is_ok();
    verified as c_char
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn verify_state_proof(proof: *const c_char) -> c_char {
    let proof_vec = c_char_to_vec(proof);
    let proof = serde_json::from_slice::<TargetCircuitProof>(proof_vec.as_slice()).unwrap();
    let verified = VERIFIER
        .verify_target_circuit_proof::<StateCircuit>(&proof)
        .is_ok();
    verified as c_char
}
