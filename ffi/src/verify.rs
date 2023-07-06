use crate::utils::{c_char_to_str, c_char_to_vec};
use libc::c_char;
use prover::{utils::init_env_and_log, zkevm, Proof};
use std::{fs::File, io::Read};

static mut VERIFIER: Option<&zkevm::Verifier> = None;

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn init_verifier(params_path: *const c_char, agg_vk_path: *const c_char) {
    init_env_and_log("ffi_verify");

    let params_path = c_char_to_str(params_path);
    let agg_vk_path = c_char_to_str(agg_vk_path);
    let mut f = File::open(agg_vk_path).unwrap();
    let mut agg_vk = vec![];
    f.read_to_end(&mut agg_vk).unwrap();

    let v = Box::new(zkevm::Verifier::from_params_dir(params_path, Some(agg_vk)));
    VERIFIER = Some(Box::leak(v))
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn verify_chunk_proof(proof: *const c_char) -> c_char {
    let proof_vec = c_char_to_vec(proof);
    let chunk_proof = serde_json::from_slice::<Proof>(proof_vec.as_slice()).unwrap();
    let verified = VERIFIER.unwrap().verify_chunk_proof(chunk_proof).is_ok();
    verified as c_char
}
