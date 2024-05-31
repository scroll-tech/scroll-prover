use integration::test_util::{load_block_traces_for_test, PARAMS_DIR};
use prover::{
    inner::{Prover, Verifier},
    utils::init_env_and_log,
    zkevm::circuit::SuperCircuit,
};

#[cfg(feature = "prove_verify")]
#[test]
fn test_inner_prove_verify() {
    let test_name = "inner_tests";
    let output_dir = init_env_and_log(test_name);
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_trace = load_block_traces_for_test().1;
    log::info!("Loaded chunk trace");

    let mut prover = Prover::<SuperCircuit>::from_params_dir(PARAMS_DIR);
    log::info!("Constructed prover");

    let proof = prover
        .load_or_gen_inner_proof(test_name, "inner", chunk_trace, Some(&output_dir))
        .unwrap();
    log::info!("Got inner snark");

    let verifier = Verifier::<SuperCircuit>::from_params_dir(PARAMS_DIR, None);
    assert!(verifier.verify_inner_snark(proof.to_snark()));
    log::info!("Finish inner snark verification");
}
