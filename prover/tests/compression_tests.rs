use aggregator::CompressionCircuit;
use prover::{
    aggregator::{Prover, Verifier},
    test_util::{
        aggregator::{load_or_gen_chunk_snark, load_or_gen_comp_evm_proof, load_or_gen_comp_snark},
        load_block_traces_for_test, PARAMS_DIR,
    },
    utils::{init_env_and_log, load_or_download_params},
    zkevm::circuit::AGG_DEGREE,
};
use std::path::Path;

#[cfg(feature = "prove_verify")]
#[test]
fn test_comp_prove_verify() {
    // 1. Init, load block traces, construct prover and verifier.

    let output_dir = init_env_and_log("comp_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let block_traces = load_block_traces_for_test().1;
    log::info!("Loaded block-traces");

    let params = load_or_download_params(PARAMS_DIR, *AGG_DEGREE).unwrap();
    let mut prover = Prover::from_params(params.clone());
    let verifier = Verifier::from_params(params);
    log::info!("Constructed prover and verifier");

    // 2. Load or generate chunk snark.
    let chunk_snark = load_or_gen_chunk_snark(&output_dir, &mut prover, block_traces);
    log::info!("Got chunk snark");

    // 3. Load or generate compression wide snark (layer-1).
    let comp_wide_snark =
        load_or_gen_comp_snark(&output_dir, "comp_wide", true, 22, &mut prover, chunk_snark);
    log::info!("Got compression wide snark (layer-1)");

    // 4. Load or generate compression EVM proof (layer-2).
    let proof = load_or_gen_comp_evm_proof(
        &output_dir,
        "comp_thin",
        false,
        *AGG_DEGREE,
        &mut prover,
        comp_wide_snark,
    );
    log::info!("Got compression EVM proof (layer-2)");

    // 5. Verify the proof.
    let yul_file_path = format!("{output_dir}/comp_verifier.yul");
    verifier.evm_verify::<CompressionCircuit>(&proof, Some(Path::new(&yul_file_path)));
}
