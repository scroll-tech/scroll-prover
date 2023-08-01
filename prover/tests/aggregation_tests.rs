use aggregator::CompressionCircuit;
use prover::{
    aggregator::{Prover, Verifier},
    common,
    config::LAYER4_DEGREE,
    test_util::{load_block_traces_for_test, PARAMS_DIR},
    utils::{chunk_trace_to_witness_block, init_env_and_log},
    zkevm, ChunkHash, ChunkProof, EvmProof, Proof,
};
use snark_verifier_sdk::Snark;
use std::env;

#[cfg(feature = "prove_verify")]
#[test]
fn test_agg_prove_verify() {
    let output_dir = init_env_and_log("agg_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let mut agg_prover = Prover::from_params_dir(PARAMS_DIR);
    log::info!("Constructed aggregation prover");

    let trace_paths: Vec<_> = (2..=3)
        .map(|i| format!("./tests/traces/bridge/{i:02}.json"))
        .collect();

    let trace_paths = vec!["./tests/traces/erc20/10_transfer.json".to_string()];

    let chunk_hashes_proofs = gen_chunk_hashes_and_proofs(&output_dir, trace_paths.as_slice());
    log::info!("Generated chunk hashes and proofs");

    // Load or generate aggregation snark (layer-3).
    let layer3_snark = agg_prover
        .load_or_gen_last_agg_snark("agg", chunk_hashes_proofs, Some(&output_dir))
        .unwrap();

    let (evm_proof, agg_verifier) =
        gen_and_verify_evm_proof(&output_dir, &mut agg_prover, layer3_snark.clone());

    gen_and_verify_normal_proof(
        &output_dir,
        &mut agg_prover,
        &agg_verifier,
        evm_proof.proof.raw_vk().to_vec(),
        layer3_snark,
    );
}

fn gen_and_verify_evm_proof(
    output_dir: &str,
    prover: &mut Prover,
    layer3_snark: Snark,
) -> (EvmProof, Verifier) {
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

    env::set_var("COMPRESSION_CONFIG", "./configs/layer4.config");
    let vk = evm_proof.proof.vk::<CompressionCircuit>();

    let params = prover.inner.params(*LAYER4_DEGREE).clone();
    common::Verifier::<CompressionCircuit>::new(params, vk).evm_verify(&evm_proof, &output_dir);
    log::info!("Generated deployment bytecode");

    env::set_var("AGG_VK_FILENAME", "vk_evm_layer4_evm.vkey");
    let verifier = Verifier::from_dirs(PARAMS_DIR, output_dir);
    log::info!("Constructed aggregator verifier");

    let success = verifier.verify_agg_evm_proof(&evm_proof.proof);
    assert!(success);
    log::info!("Finished EVM verification");

    (evm_proof, verifier)
}

fn gen_and_verify_normal_proof(
    output_dir: &str,
    prover: &mut Prover,
    verifier: &Verifier,
    raw_vk: Vec<u8>,
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

    let proof = Proof::from_snark(layer4_snark, raw_vk).unwrap();
    log::info!("Got normal proof");

    assert!(verifier.inner.verify_proof(proof));
    log::info!("Finished normal verification");
}

fn gen_chunk_hashes_and_proofs(
    output_dir: &str,
    trace_paths: &[String],
) -> Vec<(ChunkHash, ChunkProof)> {
    let mut zkevm_prover = zkevm::Prover::from_params_dir(PARAMS_DIR);
    log::info!("Constructed zkevm prover");

    let chunk_traces: Vec<_> = trace_paths
        .iter()
        .map(|trace_path| {
            env::set_var("TRACE_PATH", trace_path);
            load_block_traces_for_test().1
        })
        .collect();

    chunk_traces
        .into_iter()
        .map(|chunk_trace| {
            let witness_block = chunk_trace_to_witness_block(chunk_trace.clone()).unwrap();
            let chunk_hash = ChunkHash::from_witness_block(&witness_block, false);

            let proof = zkevm_prover
                .gen_chunk_proof(chunk_trace, None, Some(output_dir))
                .unwrap();

            (chunk_hash, proof)
        })
        .collect()
}
