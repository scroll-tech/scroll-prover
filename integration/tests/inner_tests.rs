use integration::test_util::{load_chunk_for_test, PARAMS_DIR};
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

    let chunk_trace = load_chunk_for_test().1;
    println!("hehe, chunk_trace={:?}", &chunk_trace);
    log::info!("Loaded chunk trace");

    let mut prover = Prover::<SuperCircuit>::from_params_dir(PARAMS_DIR);
    log::info!("Constructed prover");

    let snark = prover.gen_inner_snark("inner", chunk_trace).unwrap();
    log::info!("Got inner snark");

    let verifier = Verifier::<SuperCircuit>::from_params_dir(PARAMS_DIR, None);
    assert!(verifier.verify_inner_snark(snark));
    log::info!("Finish inner snark verification");
}
