use crate::utils::{c_char_to_str, c_char_to_vec};
use libc::c_char;
use std::fs::File;
use std::io::Read;
use zkevm::circuit::{EvmCircuit, StateCircuit, AGG_DEGREE, DEGREE};
use zkevm::prover::{AggCircuitProof, TargetCircuitProof};
use zkevm::utils::load_or_create_params;
use zkevm::verifier::Verifier;

static mut VERIFIER: Option<&Verifier> = None;
// static VERIFIER: Lazy<Verifier> = Lazy::new(|| {
//     println!("init ---");
//     let params_path = read_env_var("params_path", "/tmp/params".to_string());
//     let agg_vk_path = read_env_var("agg_vk_path", "/tmp/agg_vk".to_string());
//     let mut f = File::open(agg_vk_path).unwrap();
//     let mut agg_vk = vec![];
//     f.read_to_end(&mut agg_vk).unwrap();
//
//     println!("load params");
//     let params = load_or_create_params(&params_path, *DEGREE).unwrap();
//     println!("load agg-params");
//     let agg_params = load_or_create_params(&params_path, *AGG_DEGREE).unwrap();
//
//     Verifier::from_params(params, agg_params, Some(agg_vk))
// });

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn init_verifier(params_path: *const c_char, agg_vk_path: *const c_char) {
    let params_path = c_char_to_str(params_path);
    let agg_vk_path = c_char_to_str(agg_vk_path);
    let mut f = File::open(agg_vk_path).unwrap();
    let mut agg_vk = vec![];
    f.read_to_end(&mut agg_vk).unwrap();

    println!("load params");
    let params = load_or_create_params(params_path, *DEGREE).unwrap();
    let agg_params = load_or_create_params(params_path, *AGG_DEGREE).unwrap();

    let v = Box::new(Verifier::from_params(params, agg_params, Some(agg_vk)));
    VERIFIER = Some(Box::leak(v))
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn verify_agg_proof(proof: *const c_char) -> c_char {
    println!("verify agg-proof");
    let proof_vec = c_char_to_vec(proof);
    let agg_proof = serde_json::from_slice::<AggCircuitProof>(proof_vec.as_slice()).unwrap();
    // println!("proof is {:?}", agg_proof.proof);
    let verified = VERIFIER
        .unwrap()
        .verify_agg_circuit_proof(agg_proof)
        .is_ok();
    println!("verify result: {}", verified);
    verified as c_char
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn verify_evm_proof(proof: *const c_char) -> c_char {
    let proof_vec = c_char_to_vec(proof);
    let proof = serde_json::from_slice::<TargetCircuitProof>(proof_vec.as_slice()).unwrap();
    let verified = VERIFIER
        .unwrap()
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
        .unwrap()
        .verify_target_circuit_proof::<StateCircuit>(&proof)
        .is_ok();
    verified as c_char
}
