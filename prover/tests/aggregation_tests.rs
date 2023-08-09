use aggregator::CompressionCircuit;
use prover::{
    aggregator::Verifier,
    config::{LAYER4_CONFIG_PATH, LAYER4_DEGREE},
    proof::from_json_file,
    test_util::PARAMS_DIR,
    utils::{init_env_and_log, load_params},
    BatchProof,
};
use snark_verifier_sdk::rust_verify;
use std::env;

#[cfg(feature = "prove_verify")]
#[test]
fn test_agg_prove_verify() {
    let output_dir = init_env_and_log("agg_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    gen_and_verify_evm_proof(&output_dir);
}

fn gen_and_verify_evm_proof(output_dir: &str) {
    let batch_proof = BatchProof::from_json_file("batch-verify-data", "8_proof").unwrap();
    batch_proof.dump(output_dir, "batch8");
    batch_proof.clone().assert_calldata();

    let calldata = batch_proof.clone().calldata();
    log::error!("gupeng - calldata =\n{:?}", calldata);

    let proof = batch_proof.clone().proof_to_verify();
    env::set_var("COMPRESSION_CONFIG", &*LAYER4_CONFIG_PATH);
    let vk = proof.vk::<CompressionCircuit>();

    let params = load_params(PARAMS_DIR, *LAYER4_DEGREE, None).unwrap();

    let accept = rust_verify(
        &params,
        &vk,
        &proof.instances(),
        proof.proof(),
    );
    assert!(accept);

    let v = Verifier::from_dirs(PARAMS_DIR, "./test_assets");
    let success = v.verify_agg_evm_proof(batch_proof);
    assert!(success);
    log::info!("Generated deployment bytecode");
}
