use prover::{
    aggregator::Prover,
    io::{load_snark, write_snark},
    test_util::{load_block_traces_for_test, PARAMS_DIR},
    utils::{gen_rng, init_env_and_log, load_or_download_params},
    zkevm::circuit::{SuperCircuit, AGG_DEGREE},
};
use snark_verifier_sdk::Snark;
use std::env::set_var;
use types::eth::BlockTrace;

#[cfg(feature = "prove_verify")]
#[test]
fn test_comp_prove_verify() {
    // 1. Init, load block traces and build prover.

    let output_dir = init_env_and_log("comp_tests");
    log::info!("Inited ENV and created output-dir {output_dir}");

    let block_traces = load_block_traces_for_test().1;
    log::info!("Loaded block-traces");

    let params = load_or_download_params(PARAMS_DIR, *AGG_DEGREE).unwrap();
    let mut prover = Prover::from_params(params);
    log::info!("Build agg-prover");

    // 2. Load or generate chunk snark.
    let chunk_snark = load_or_gen_chunk_snark(&output_dir, &mut prover, block_traces);
    log::info!("Got chunk snark");

    // 3. Load or generate compression wide snark (layer-1).
    let comp_wide_snark =
        load_or_gen_comp_snark(&output_dir, "comp_wide", true, &mut prover, chunk_snark);
    log::info!("Got compression wide snark (layer-1)");

    // 4. Load or generate compression thin snark (layer-2).
    let comp_thin_snark = load_or_gen_comp_snark(
        &output_dir,
        "comp_thin",
        false,
        &mut prover,
        comp_wide_snark,
    );
    log::info!("Got compression thin snark (layer-2)");

    // TODO
}

fn load_or_gen_chunk_snark(
    output_dir: &str,
    prover: &mut Prover,
    chunk_trace: Vec<BlockTrace>,
) -> Snark {
    let file_path = format!("{output_dir}/chunk_snark.json");

    load_snark(&file_path).unwrap().unwrap_or_else(|| {
        let snark = prover.gen_chunk_proof::<SuperCircuit>(chunk_trace).unwrap();
        write_snark(&file_path, &snark);

        snark
    })
}

fn load_or_gen_comp_snark(
    output_dir: &str,
    id: &str,
    is_fresh: bool,
    prover: &mut Prover,
    prev_snark: Snark,
) -> Snark {
    set_var("VERIFY_CONFIG", "./configs/{id}.config");
    let file_path = format!("{output_dir}/{id}_snark.json");

    load_snark(&file_path).unwrap().unwrap_or_else(|| {
        let rng = gen_rng();
        let snark = prover.gen_comp_proof(id, is_fresh, *AGG_DEGREE, rng, prev_snark);
        write_snark(&file_path, &snark);

        snark
    })
}
