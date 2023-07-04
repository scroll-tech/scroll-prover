use crate::utils::{c_char_to_str, c_char_to_vec};
use libc::c_char;
use prover::{aggregator, config::AGG_DEGREE, utils::init_env_and_log, zkevm, Proof};
use std::{fs::File, io::Read};

static mut CHUNK_VERIFIER: Option<&zkevm::Verifier> = None;
static mut AGG_VERIFIER: Option<&aggregator::Verifier> = None;

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn init_chunk_verifier(params_dir: *const c_char, vk_path: *const c_char) {
    init_env_and_log("ffi_chunk_verify");

    let vk_path = c_char_to_str(vk_path);
    let mut f = File::open(vk_path).unwrap();
    let mut vk = vec![];
    f.read_to_end(&mut vk).unwrap();

    let params_dir = c_char_to_str(params_dir);
    let verifier = Box::new(zkevm::Verifier::from_params_dir(params_dir, Some(vk)));

    CHUNK_VERIFIER = Some(Box::leak(verifier));
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn init_agg_verifier(params_dir: *const c_char, vk_path: *const c_char) {
    init_env_and_log("ffi_agg_verify");

    let vk_path = c_char_to_str(vk_path);
    let mut f = File::open(vk_path).unwrap();
    let mut vk = vec![];
    f.read_to_end(&mut vk).unwrap();

    let params_dir = c_char_to_str(params_dir);
    let verifier = Box::new(aggregator::Verifier::from_params_dir(
        params_dir,
        *AGG_DEGREE,
        Some(vk),
    ));

    AGG_VERIFIER = Some(Box::leak(verifier));
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn verify_chunk_proof(proof: *const c_char) -> c_char {
    let proof_vec = c_char_to_vec(proof);
    let proof = serde_json::from_slice::<Proof>(proof_vec.as_slice()).unwrap();
    let verified = CHUNK_VERIFIER.unwrap().verify_chunk_proof(proof).is_ok();

    verified as c_char
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn verify_agg_proof(proof: *const c_char) -> c_char {
    let proof_vec = c_char_to_vec(proof);
    let proof = serde_json::from_slice::<Proof>(proof_vec.as_slice()).unwrap();
    let verified = AGG_VERIFIER.unwrap().verify_agg_proof(proof).is_ok();

    verified as c_char
}
