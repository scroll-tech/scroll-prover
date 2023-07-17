use crate::utils::{c_char_to_str, c_char_to_vec, vec_to_c_char};
use libc::c_char;
use prover::{
    utils::init_env_and_log,
    zkevm::{Prover, Verifier},
    Proof,
};
use std::{cell::OnceCell, fs::File, io::Read};
use types::eth::BlockTrace;

static mut ZKEVM_PROVER: OnceCell<Prover> = OnceCell::new();
static mut ZKEVM_VERIFIER: Option<&Verifier> = None;

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn init_zkevm_prover(params_dir: *const c_char) {
    init_env_and_log("ffi_zkevm_prove");

    let params_dir = c_char_to_str(params_dir);
    let prover = Prover::from_params_dir(params_dir);
    ZKEVM_PROVER.set(prover).unwrap();
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn init_zkevm_verifier(params_dir: *const c_char, vk_path: *const c_char) {
    init_env_and_log("ffi_zkevm_verify");

    let vk_path = c_char_to_str(vk_path);
    let mut f = File::open(vk_path).unwrap();
    let mut vk = vec![];
    f.read_to_end(&mut vk).unwrap();

    let params_dir = c_char_to_str(params_dir);
    let verifier = Box::new(Verifier::from_params_dir(params_dir, Some(vk)));

    ZKEVM_VERIFIER = Some(Box::leak(verifier));
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
pub unsafe extern "C" fn verify_chunk_proof(proof: *const c_char) -> c_char {
    let proof = c_char_to_vec(proof);
    let proof = serde_json::from_slice::<Proof>(proof.as_slice()).unwrap();

    let verified = ZKEVM_VERIFIER.unwrap().verify_chunk_proof(proof).is_ok();
    verified as c_char
}
