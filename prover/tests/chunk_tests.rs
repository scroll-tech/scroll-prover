use aggregator::CompressionCircuit;
use halo2_proofs::{
    halo2curves::bn256::G1Affine,
    plonk::{keygen_vk, VerifyingKey},
    SerdeFormat,
};
use prover::{
    config::LAYER2_DEGREE,
    io::serialize_vk,
    test_util::{load_block_traces_for_test, PARAMS_DIR},
    utils::{chunk_trace_to_witness_block, init_env_and_log},
    zkevm::{Prover, Verifier},
    Proof,
};
use snark_verifier_sdk::{verify_snark_shplonk, Snark};
use std::io::Cursor;

const TEST_NAME: &str = "chunk_tests";

#[cfg(feature = "prove_verify")]
#[test]
fn test_chunk_prove_verify() {
    let output_dir = init_env_and_log(TEST_NAME);
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_trace = load_block_traces_for_test().1;
    log::info!("Loaded chunk trace");

    let witness_block = chunk_trace_to_witness_block(chunk_trace).unwrap();
    log::info!("Got witness block");

    let mut prover = Prover::from_params_dir(PARAMS_DIR);
    log::info!("Constructed prover");

    // Load or generate compression wide snark (layer-1).
    let layer1_snark = prover
        .load_or_gen_last_snark(TEST_NAME, witness_block, Some(&output_dir))
        .unwrap();

    let (evm_proof, verifier) =
        gen_and_verify_evm_proof(&output_dir, &mut prover, layer1_snark.clone());

    gen_and_verify_normal_proof(
        &output_dir,
        &mut prover,
        &verifier,
        evm_proof.raw_vk().to_vec(),
        layer1_snark,
    );
}

fn gen_and_verify_evm_proof(
    output_dir: &str,
    prover: &mut Prover,
    layer1_snark: Snark,
) -> (Proof, Verifier) {
    // Load or generate compression EVM proof (layer-2).
    let proof = prover
        .inner
        .load_or_gen_comp_evm_proof(
            TEST_NAME,
            "layer2",
            false,
            *LAYER2_DEGREE,
            layer1_snark,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression-EVM-proof (layer-2)");

    let params = prover.inner.params(*LAYER2_DEGREE).clone();
    let vk = proof.vk::<CompressionCircuit>();
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
    layer1_snark: Snark,
) {
    // Load or generate compression thin snark (layer-2).
    let layer2_snark = prover
        .inner
        .load_or_gen_comp_snark(
            TEST_NAME,
            "layer2",
            false,
            *LAYER2_DEGREE,
            layer1_snark,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression thin snark (layer-2)");

    log::error!("gupeng - chunk_tests - 1 - pk.get_vk()");
    let params = prover.inner.params(*LAYER2_DEGREE).clone();
    let vk = prover.inner.pk("layer2").unwrap().get_vk();
    log::error!("gupeng - original_vk = {:#?}", vk);
    assert!(verify_snark_shplonk::<CompressionCircuit>(
        &params,
        layer2_snark.clone(),
        &vk
    ));

    log::error!("gupeng - chunk_tests - 2 - serialize then read");
    let raw_vk = serialize_vk(&vk);
    let new_vk = VerifyingKey::<G1Affine>::read::<_, CompressionCircuit>(
        &mut Cursor::new(raw_vk),
        SerdeFormat::Processed,
    )
    .unwrap();
    log::error!("gupeng - deserialized_vk = {:#?}", new_vk);
    assert!(verify_snark_shplonk::<CompressionCircuit>(
        &params,
        layer2_snark,
        &new_vk
    ));

    /*
        let proof = Proof::from_snark(&layer2_snark, raw_vk).unwrap();
        log::info!("Got normal proof");

        assert!(verifier.verify_chunk_proof(proof));
    */
    log::info!("Finish normal verification");
}
