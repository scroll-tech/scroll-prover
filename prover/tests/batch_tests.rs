use aggregator::CompressionCircuit;
use prover::{
    aggregator::{Prover, Verifier},
    common,
    config::{LAYER4_CONFIG_PATH, LAYER4_DEGREE},
    proof::from_json_file,
    test_util::PARAMS_DIR,
    utils::init_env_and_log,
    BatchProof, ChunkHash, ChunkProof,
};
use serde_derive::{Deserialize, Serialize};
use snark_verifier_sdk::Snark;
use std::env;

#[cfg(feature = "prove_verify")]
#[test]
fn test_batch_prove_verify() {
    let output_dir = init_env_and_log("batch_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let mut agg_prover = Prover::from_params_dir(PARAMS_DIR);
    log::info!("Constructed aggregation prover");

    let chunk_hashes_proofs = load_chunk_hashes_and_proofs("tests/test_data", "1");
    let (chunk_hashes, chunk_proofs): (Vec<_>, Vec<_>) =
        chunk_hashes_proofs.clone().into_iter().unzip();
    log::info!("Loaded chunk-proofs: chunk-hashes = {chunk_hashes:#?}");

    // Load or generate aggregation snark (layer-3).
    let layer3_snark = agg_prover
        .load_or_gen_last_agg_snark("agg", chunk_hashes_proofs, Some(&output_dir))
        .unwrap();

    let agg_verifier = gen_and_verify_evm_proof(&output_dir, &mut agg_prover, layer3_snark.clone());

    gen_and_verify_normal_proof(&output_dir, &mut agg_prover, &agg_verifier, layer3_snark);
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchTaskDetail {
    chunk_infos: Vec<ChunkHash>,
    chunk_proofs: Vec<ChunkProof>,
}

fn load_chunk_hashes_and_proofs(dir: &str, filename: &str) -> Vec<(ChunkHash, ChunkProof)> {
    let batch_task_detail: BatchTaskDetail = from_json_file(dir, filename).unwrap();
    let chunk_hashes = batch_task_detail.chunk_infos;
    let chunk_proofs = batch_task_detail.chunk_proofs;

    chunk_hashes[..]
        .to_vec()
        .into_iter()
        .zip(chunk_proofs[..].to_vec().into_iter())
        .collect()
}

fn gen_and_verify_evm_proof(
    output_dir: &str,
    prover: &mut Prover,
    layer3_snark: Snark,
) -> Verifier {
    // Load or generate compression EVM proof (layer-4).
    let evm_proof = prover
        .inner
        .load_or_gen_comp_evm_proof(
            "evm",
            "layer4",
            true,
            *LAYER4_DEGREE,
            layer3_snark,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression-EVM-proof (layer-4)");

    env::set_var("COMPRESSION_CONFIG", &*LAYER4_CONFIG_PATH);
    let vk = evm_proof.proof.vk::<CompressionCircuit>();

    let params = prover.inner.params(*LAYER4_DEGREE).clone();
    common::Verifier::<CompressionCircuit>::new(params, vk).evm_verify(&evm_proof, &output_dir);
    log::info!("Generated deployment bytecode");

    env::set_var("AGG_VK_FILENAME", "vk_evm_layer4_evm.vkey");
    let verifier = Verifier::from_dirs(PARAMS_DIR, output_dir);
    log::info!("Constructed aggregator verifier");

    let batch_proof = BatchProof::from(evm_proof.proof.clone());
    batch_proof.dump(output_dir, "agg").unwrap();
    batch_proof.clone().assert_calldata();

    let success = verifier.verify_agg_evm_proof(batch_proof);
    assert!(success);
    log::info!("Finished EVM verification");

    verifier
}

fn gen_and_verify_normal_proof(
    output_dir: &str,
    prover: &mut Prover,
    verifier: &Verifier,
    layer3_snark: Snark,
) {
    // Load or generate compression thin snark (layer-4).
    let layer4_snark = prover
        .inner
        .load_or_gen_comp_snark(
            "layer4",
            "layer4",
            true,
            *LAYER4_DEGREE,
            layer3_snark,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression thin snark (layer-4)");

    assert!(verifier.inner.verify_snark(layer4_snark));
    log::info!("Finished normal verification");
}
