use aggregator::CompressionCircuit;
use prover::{
    aggregator::{Prover, Verifier},
    common,
    config::{LAYER4_CONFIG_PATH, LAYER4_DEGREE},
    proof::from_json_file,
    test_util::{load_block_traces_for_test, PARAMS_DIR},
    utils::{chunk_trace_to_witness_block, init_env_and_log, load_params},
    zkevm, BatchProof, ChunkHash, ChunkProof, EvmProof, Proof,
};
use serde_derive::{Deserialize, Serialize};
use snark_verifier_sdk::Snark;
use std::env;

#[cfg(feature = "prove_verify")]
#[test]
fn test_agg_prove_verify() {
    let output_dir = init_env_and_log("agg_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    gen_and_verify_evm_proof(&output_dir);
}

fn gen_and_verify_evm_proof(output_dir: &str) {
    let evm_proof = EvmProof::from_json_file(output_dir, "layer4_evm").unwrap();
    log::info!("Got compression-EVM-proof (layer-4)");

    env::set_var("COMPRESSION_CONFIG", &*LAYER4_CONFIG_PATH);
    let vk = evm_proof.proof.vk::<CompressionCircuit>();
    let params = load_params(PARAMS_DIR, *LAYER4_DEGREE, None).unwrap();
    common::Verifier::<CompressionCircuit>::new(params, vk).evm_verify(&evm_proof, &output_dir);
    log::info!("Generated deployment bytecode");
}
