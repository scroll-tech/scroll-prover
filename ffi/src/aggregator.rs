use crate::utils::{c_char_to_str, c_char_to_vec, vec_to_c_char, OUTPUT_DIR};
use libc::c_char;
use prover::{
    aggregator::{Prover, Verifier},
    utils::init_env_and_log,
    ChunkHash, Proof,
};
use std::{cell::OnceCell, fs::File, io::Read};

static mut AGG_PROVER: OnceCell<Prover> = OnceCell::new();
static mut AGG_VERIFIER: Option<&Verifier> = None;

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn init_agg_prover(params_dir: *const c_char) {
    init_env_and_log("ffi_agg_prove");

    let params_dir = c_char_to_str(params_dir);

    let prover = Prover::from_params_dir(params_dir);
    AGG_PROVER.set(prover).unwrap();
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
    let verifier = Box::new(Verifier::from_params_dir(params_dir, &vk));

    AGG_VERIFIER = Some(Box::leak(verifier));
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn create_agg_proof(
    chunk_hashes: *const c_char,
    chunk_proofs: *const c_char,
) -> *const c_char {
    let chunk_hashes = c_char_to_vec(chunk_hashes);
    let chunk_proofs = c_char_to_vec(chunk_proofs);

    let chunk_hashes = serde_json::from_slice::<Vec<ChunkHash>>(&chunk_hashes).unwrap();
    let chunk_proofs = serde_json::from_slice::<Vec<Proof>>(&chunk_proofs).unwrap();
    assert_eq!(chunk_hashes.len(), chunk_proofs.len());

    let chunks = chunk_hashes
        .into_iter()
        .zip(chunk_proofs.into_iter())
        .collect();

    let proof = AGG_PROVER
        .get_mut()
        .unwrap()
        .gen_agg_proof(chunks, OUTPUT_DIR.as_deref())
        .unwrap();

    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    vec_to_c_char(proof_bytes)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn verify_agg_proof(proof: *const c_char) -> c_char {
    let proof = c_char_to_vec(proof);
    let proof = serde_json::from_slice::<Proof>(proof.as_slice()).unwrap();

    let verified = AGG_VERIFIER.unwrap().verify_agg_proof(proof);
    verified as c_char
}
