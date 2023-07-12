use aggregator::CompressionCircuit;
use halo2_proofs::{halo2curves::bn256::G1Affine, plonk::VerifyingKey, SerdeFormat};
use prover::{
    aggregator::{Prover, Verifier},
    config::{AGG_LAYER1_DEGREE, AGG_LAYER2_DEGREE, INNER_DEGREE},
    io::serialize_vk,
    test_util::{
        aggregator::{gen_comp_evm_proof, load_or_gen_comp_snark, load_or_gen_real_chunk_snark},
        load_block_traces_for_test, PARAMS_DIR,
    },
    utils::{chunk_trace_to_witness_block, init_env_and_log},
};
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier_sdk::{evm_verify, gen_evm_verifier, verify_snark_shplonk, CircuitExt};
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

    let mut prover = Prover::from_params_dir(
        PARAMS_DIR,
        &[*INNER_DEGREE, *AGG_LAYER1_DEGREE, *AGG_LAYER2_DEGREE],
    );
    log::info!("Constructed prover");

    // Load or generate chunk snark.
    let chunk_snark = load_or_gen_real_chunk_snark(&output_dir, "comp", &mut prover, witness_block);
    log::info!("Got chunk-snark");

    // Load or generate compression wide snark (layer-1).
    let layer1_snark = load_or_gen_comp_snark(
        &output_dir,
        "agg_layer1",
        true,
        *AGG_LAYER1_DEGREE,
        &mut prover,
        chunk_snark,
    );
    log::info!("Got compression wide snark (layer-1)");

    // Load or generate compression EVM proof (layer-2).
    let proof = gen_comp_evm_proof(
        &output_dir,
        "agg_layer2",
        false,
        *AGG_LAYER2_DEGREE,
        &mut prover,
        layer1_snark,
    );
    log::info!("Got compression EVM proof (layer-2)");

    // Test vk deserialization.
    let vk1 = prover.pk("agg_layer2").unwrap().get_vk().clone();
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
    let params = prover.params(*AGG_LAYER2_DEGREE).clone();
    // let vk = prover.pk("agg_layer2").unwrap().get_vk().clone();
    let verifier = Verifier::new(params, Some(vk2));
    let yul_file_path = format!("{output_dir}/comp_verifier.yul");
    verifier.evm_verify::<CompressionCircuit>(&proof, Some(Path::new(&yul_file_path)));
    log::info!("Finish EVM verify");
}
