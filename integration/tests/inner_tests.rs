use integration::test_util::{load_chunk_for_test, PARAMS_DIR};
use prover::{inner::Verifier, utils::init_env_and_log, zkevm::circuit::SuperCircuit};

#[cfg(feature = "prove_verify")]
#[test]
fn test_inner_prove_verify() {
    use itertools::Itertools;
    use prover::config::ZKEVM_DEGREES;

    let test_name = "inner_tests";
    let output_dir = init_env_and_log(test_name);
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let params_map = prover::common::Prover::load_params_map(
        PARAMS_DIR,
        &ZKEVM_DEGREES.iter().copied().collect_vec(),
    );

    let chunk_trace = load_chunk_for_test().1;
    log::info!("Loaded chunk trace");

    let inner_prover = prover::common::Prover::from_params_map(&params_map);
    let mut prover = prover::inner::Prover::<SuperCircuit>::from(inner_prover);
    log::info!("Constructed prover");

    let snark = prover.gen_inner_snark("inner", chunk_trace).unwrap();
    log::info!("Got inner snark");

    let verifier = Verifier::<SuperCircuit>::from_params_map(&params_map, None);
    assert!(verifier.verify_inner_snark(snark));
    log::info!("Finish inner snark verification");
}
