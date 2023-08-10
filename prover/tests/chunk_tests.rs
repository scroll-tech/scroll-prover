use aggregator::CompressionCircuit;
use prover::{
    config::{LAYER2_CONFIG_PATH, LAYER2_DEGREE},
    test_util::{load_block_traces_for_test, PARAMS_DIR},
    utils::{chunk_trace_to_witness_block, init_env_and_log},
    zkevm::{Prover, Verifier},
};
use snark_verifier_sdk::{verify_snark_shplonk, Snark};
use std::env;

#[cfg(feature = "prove_verify")]
#[test]
fn test_chunk_prove_verify() {
    let output_dir = init_env_and_log("chunk_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_trace = load_block_traces_for_test().1;
    log::info!("Loaded chunk trace");

    let witness_block = chunk_trace_to_witness_block(chunk_trace).unwrap();
    log::info!("Got witness block");

    let mut prover = Prover::from_params_dir(PARAMS_DIR);
    log::info!("Constructed prover");

    // Load or generate compression wide snark (layer-1).
    let layer1_snark = prover
        .inner
        .load_or_gen_last_chunk_snark("layer1", &witness_block, Some(&output_dir))
        .unwrap();

    let verifier = gen_and_verify_evm_proof(&output_dir, &mut prover, layer1_snark.clone());
    // gen_and_verify_normal_proof(&output_dir, &mut prover, &verifier, layer1_snark);
}

fn gen_and_verify_evm_proof(
    output_dir: &str,
    prover: &mut Prover,
    layer1_snark: Snark,
) -> Verifier {
    // Load or generate compression thin SNARK (layer-2).
    let layer2_snark = prover
        .inner
        .load_or_gen_comp_snark(
            "layer2",
            "layer2",
            true,
            *LAYER2_DEGREE,
            layer1_snark.clone(),
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression thin snark (layer-2)");

    let params = prover.inner.params(*LAYER2_DEGREE).clone();
    assert_eq!(
        verify_snark_shplonk::<CompressionCircuit>(
            &params,
            layer2_snark,
            prover.inner.pk("layer2").unwrap().get_vk(),
        ),
        true,
    );

    // Load or generate compression EVM proof (layer-2).
    let evm_proof = prover
        .inner
        .load_or_gen_comp_evm_proof(
            "evm",
            "layer2",
            true,
            *LAYER2_DEGREE,
            layer1_snark,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression-EVM-proof (layer-2)");

    env::set_var("COMPRESSION_CONFIG", &*LAYER2_CONFIG_PATH);
    let vk = evm_proof.proof.vk::<CompressionCircuit>();

    let params = prover.inner.params(*LAYER2_DEGREE).clone();
    let verifier = Verifier::new(params, vk);
    log::info!("Constructed verifier");

    verifier.inner.evm_verify(&evm_proof, &output_dir);
    log::info!("Finish EVM verification");

    verifier
}

fn gen_and_verify_normal_proof(
    output_dir: &str,
    prover: &mut Prover,
    verifier: &Verifier,
    layer1_snark: Snark,
) {
    // Load or generate compression thin snark (layer-2).
    let layer2_snark = prover
        .inner
        .load_or_gen_comp_snark(
            "layer2",
            "layer2",
            true,
            *LAYER2_DEGREE,
            layer1_snark,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression thin snark (layer-2)");

    assert!(verifier.inner.verify_snark(layer2_snark));
    log::info!("Finish normal verification");
}
