use aggregator::CompressionCircuit;
use halo2_proofs::{halo2curves::bn256::G1Affine, plonk::VerifyingKey, SerdeFormat};
use prover::{
    aggregator::{Prover, Verifier},
    config::{LAYER1_DEGREE, LAYER2_DEGREE, ZKEVM_DEGREES},
    io::serialize_vk,
    test_util::{load_block_traces_for_test, PARAMS_DIR},
    utils::{chunk_trace_to_witness_block, init_env_and_log},
};
use std::{io::Cursor, path::Path};

#[cfg(feature = "prove_verify")]
#[test]
fn test_comp_prove_verify() {
    // Init, load block traces and construct prover.

    let output_dir = init_env_and_log("comp_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_trace = load_block_traces_for_test().1;
    log::info!("Loaded chunk-trace");

    let witness_block = chunk_trace_to_witness_block(chunk_trace).unwrap();
    log::info!("Got witness-block");

    let mut zkevm_prover = Prover::from_params_dir(PARAMS_DIR, &*ZKEVM_DEGREES);
    log::info!("Constructed zkevm-prover");

    // Load or generate inner snark.
    let inner_snark = zkevm_prover
        .load_or_gen_inner_snark("layer0", witness_block, Some(&output_dir))
        .unwrap();
    log::info!("Got inner-snark");

    // Load or generate compression wide snark (layer-1).
    let layer1_snark = zkevm_prover
        .load_or_gen_comp_snark(
            "layer1_0",
            "layer1",
            true,
            *LAYER1_DEGREE,
            inner_snark,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression-wide-snark (layer-1)");

    // Load or generate compression EVM proof (layer-2).
    let proof = zkevm_prover
        .gen_comp_evm_proof(
            "layer2_0",
            "layer2",
            false,
            *LAYER2_DEGREE,
            layer1_snark,
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Got compression-EVM-proof (layer-2)");

    // Test vk deserialization.
    let vk1 = zkevm_prover.pk("layer2").unwrap().get_vk().clone();
    let raw_vk1 = serialize_vk(&vk1);
    let mut vk2 = VerifyingKey::<G1Affine>::read::<_, CompressionCircuit>(
        &mut Cursor::new(&raw_vk1),
        SerdeFormat::Processed,
    )
    .unwrap();
    let raw_vk2 = serialize_vk(&vk2);
    assert_eq!(raw_vk1, raw_vk2);
    log::error!("test - vk1 = {:#?}", vk1);
    log::error!("test - vk2 = {:#?}", vk2);

    // Construct verifier and EVM verify.
    let params = zkevm_prover.params(*LAYER2_DEGREE).clone();
    let verifier = Verifier::new(params, Some(vk2));
    let yul_file_path = format!("{output_dir}/comp_verifier.yul");
    verifier.evm_verify::<CompressionCircuit>(&proof, Some(Path::new(&yul_file_path)));
    log::info!("Finish EVM verify");
}
