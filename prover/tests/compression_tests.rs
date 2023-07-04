use aggregator::CompressionCircuit;
use prover::{
    aggregator::{Prover, Verifier},
    config::{AGG_DEGREE, ALL_DEGREES},
    test_util::{
        aggregator::{load_or_gen_chunk_snark, load_or_gen_comp_evm_proof, load_or_gen_comp_snark},
        load_block_traces_for_test, PARAMS_DIR,
    },
    utils::{chunk_trace_to_witness_block, init_env_and_log},
};
use std::path::Path;

#[cfg(feature = "prove_verify")]
#[test]
fn test_comp_prove_verify() {
    // Init, load block traces, construct prover and verifier.

    let output_dir = init_env_and_log("comp_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_trace = load_block_traces_for_test().1;
    log::info!("Loaded chunk-trace");

    let mut prover = Prover::from_params_dir(PARAMS_DIR, &*ALL_DEGREES);
    let verifier = Verifier::from_params_dir(PARAMS_DIR, *AGG_DEGREE, None);
    log::info!("Constructed prover and verifier");

    // Convert chunk trace to witness block.
    let witness_block = chunk_trace_to_witness_block(chunk_trace).unwrap();

    // Load or generate chunk snark.
    let chunk_snark = load_or_gen_chunk_snark(&output_dir, &mut prover, witness_block);
    log::info!("Got chunk snark");

    // Load or generate compression wide snark (layer-1).
    let layer1_snark =
        load_or_gen_comp_snark(&output_dir, "comp_wide", true, 22, &mut prover, chunk_snark);
    log::info!("Got compression wide snark (layer-1)");

    // Load or generate compression EVM proof (layer-2).
    let proof = load_or_gen_comp_evm_proof(
        &output_dir,
        "comp_thin",
        false,
        *AGG_DEGREE,
        &mut prover,
        layer1_snark,
    );
    log::info!("Got compression EVM proof (layer-2)");

    // Verify the proof.
    let yul_file_path = format!("{output_dir}/comp_verifier.yul");
    verifier.evm_verify::<CompressionCircuit>(&proof, Some(Path::new(&yul_file_path)));
}
