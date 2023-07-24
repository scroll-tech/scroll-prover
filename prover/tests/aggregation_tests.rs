use aggregator::CompressionCircuit;
use prover::{
    aggregator::{Prover, Verifier},
    config::LAYER4_DEGREE,
    test_util::{load_block_traces_for_test, PARAMS_DIR},
    utils::{chunk_trace_to_witness_block, init_env_and_log},
    zkevm, ChunkHash, Proof,
};
use snark_verifier_sdk::Snark;
use std::env;
use types::eth::BlockTrace;

#[cfg(feature = "prove_verify")]
#[test]
fn test_agg_prove_verify() {
    let output_dir = init_env_and_log("agg_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let mut zkevm_prover = zkevm::Prover::from_params_dir(PARAMS_DIR);
    let mut agg_prover = Prover::from_params_dir(PARAMS_DIR);
    log::info!("Constructed zkevm and aggregation provers");

    let trace_paths: Vec<_> = (2..=3)
        .map(|i| format!("./tests/traces/bridge/{i:02}.json"))
        .collect();

    let (chunk_hashes_snarks, last_chunk_trace) = gen_chunk_hashes_snarks_and_last_trace(
        &output_dir,
        &mut zkevm_prover,
        trace_paths.as_slice(),
    );
    log::info!("Generated chunk hashes and proofs");

    // Load or generate aggregation snark (layer-3).
    let layer3_snark = agg_prover
        .load_or_gen_last_agg_snark(
            "agg",
            chunk_hashes_snarks,
            &last_chunk_trace,
            Some(&output_dir),
        )
        .unwrap();

    let (evm_proof, agg_verifier) =
        gen_and_verify_evm_proof(&output_dir, &mut agg_prover, layer3_snark.clone());

    gen_and_verify_normal_proof(
        &output_dir,
        &mut agg_prover,
        &agg_verifier,
        evm_proof.raw_vk().to_vec(),
        layer3_snark,
    );
}

fn gen_and_verify_evm_proof(
    output_dir: &str,
    prover: &mut Prover,
    layer3_snark: Snark,
) -> (Proof, Verifier) {
    // Load or generate compression EVM proof (layer-4).
    let proof = prover
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
    let vk = proof.vk::<CompressionCircuit>();

    let params = prover.inner.params(*LAYER4_DEGREE).clone();
    let verifier = Verifier::new(params, vk);
    log::info!("Constructed verifier");

    verifier.inner.evm_verify(&proof, &output_dir);
    log::info!("Finish EVM verification");

    (proof, verifier)
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

    let proof = Proof::from_snark(&layer4_snark, raw_vk).unwrap();
    log::info!("Got normal proof");

    assert!(verifier.verify_agg_proof(proof));
    log::info!("Finish normal verification");
}

fn gen_chunk_hashes_snarks_and_last_trace(
    output_dir: &str,
    zkevm_prover: &mut zkevm::Prover,
    trace_paths: &[String],
) -> (Vec<(ChunkHash, Snark)>, Vec<BlockTrace>) {
    let chunk_traces: Vec<_> = trace_paths
        .iter()
        .map(|trace_path| {
            env::set_var("TRACE_PATH", trace_path);
            load_block_traces_for_test().1
        })
        .collect();

    let last_chunk_trace = chunk_traces.last().unwrap().clone();

    let chunk_hashes_snarks = chunk_traces
        .into_iter()
        .map(|chunk_trace| {
            let witness_block = chunk_trace_to_witness_block(chunk_trace.clone()).unwrap();
            let chunk_hash = ChunkHash::from_witness_block(&witness_block, false);

            let snark = zkevm_prover
                .gen_chunk_snark(chunk_trace, None, Some(output_dir))
                .unwrap();

            (chunk_hash, snark)
        })
        .collect();

    (chunk_hashes_snarks, last_chunk_trace)
}
