use integration::test_util::load_chunk_for_test;
use prover::{
    fold::Prover,
    utils::init_env_and_log,
    zkevm::circuit::SuperCircuit,
};

#[cfg(feature = "prove_verify")]
#[test]
fn test_fold_prove() {
    let test_name = "fold_tests";
    let output_dir = init_env_and_log(test_name);
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_trace = load_chunk_for_test().1;
    log::info!("Loaded chunk trace");

    //let mut prover = Prover::<SuperCircuit>::from_params_dir(PARAMS_DIR);
    let mut prover = Prover::<SuperCircuit>::default();

    prover.fold("fold", chunk_trace).unwrap();
    log::info!("finish folding");
}
