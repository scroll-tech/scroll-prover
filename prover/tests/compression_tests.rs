use aggregator::CompressionCircuit;
use prover::{
    aggregator::{Prover, Verifier},
    io::{load_snark, write_snark},
    test_util::{
        aggregator::{load_or_gen_chunk_snark, load_or_gen_comp_evm_proof, load_or_gen_comp_snark},
        load_block_traces_for_test, PARAMS_DIR,
    },
    utils::{gen_rng, init_env_and_log, load_or_download_params},
    zkevm::circuit::{SuperCircuit, AGG_DEGREE},
    Proof,
};
use snark_verifier_sdk::Snark;
use std::{
    env::set_var,
    path::{Path, PathBuf},
};
use types::eth::BlockTrace;

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
        load_or_gen_comp_snark(&output_dir, "comp_wide", true, &mut prover, chunk_snark);
    log::info!("Got compression wide snark (layer-1)");

    // 4. Load or generate compression EVM proof (layer-2).
    let proof = load_or_gen_comp_evm_proof(
        &output_dir,
        "comp_thin",
        false,
        &mut prover,
        comp_wide_snark,
    );
    log::info!("Got compression EVM proof (layer-2)");

    // 5. Verify the proof.
    let yul_file_path = format!("{output_dir}/comp_verifier.yul");
    verifier.evm_verify::<CompressionCircuit>(&proof, Some(Path::new(&yul_file_path)));
}
