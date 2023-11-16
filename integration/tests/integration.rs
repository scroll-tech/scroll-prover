use halo2_proofs::{
    plonk::{keygen_pk2, keygen_vk},
    poly::commitment::Params,
};
use integration::test_util::{
    load_block_traces_for_test, parse_trace_path_from_mode, prepare_circuit_capacity_checker,
    run_circuit_capacity_checker, PARAMS_DIR,
};
use prover::{
    config::INNER_DEGREE,
    io::serialize_vk,
    utils::{get_block_trace_from_file, init_env_and_log, load_params, short_git_version},
    zkevm::circuit::{block_traces_to_witness_block, SuperCircuit, TargetCircuit},
};
use std::time::Duration;
use zkevm_circuits::util::SubCircuit;

#[test]
fn test_short_git_version() {
    init_env_and_log("integration");

    let git_version = short_git_version();
    log::info!("short_git_version = {git_version}");

    assert_eq!(git_version.len(), 7);
}

#[ignore]
#[test]
fn test_load_params() {
    init_env_and_log("integration");
    log::info!("start");

    // Check params downsize.
    let params19 = load_params(PARAMS_DIR, 19, None).unwrap();
    let params25 = load_params(PARAMS_DIR, 25, None).unwrap();
    assert_eq!(params19.s_g2(), params25.s_g2());
    log::info!("params s_g2 = {:?}", params19.s_g2());

    let mut downsized_params19 = params25;
    downsized_params19.downsize(19);

    assert_eq!(params19.n, downsized_params19.n);
    assert_eq!(params19.g2(), downsized_params19.g2());
    assert_eq!(params19.s_g2(), downsized_params19.s_g2());
}

#[ignore]
#[test]
fn test_cs_same_for_vk_consistent() {
    let params = load_params(PARAMS_DIR, *INNER_DEGREE, None).unwrap();
    let dummy_circuit = SuperCircuit::dummy_inner_circuit();

    let pk = keygen_pk2(&params, &dummy_circuit).unwrap();
    let vk = keygen_vk(&params, &dummy_circuit).unwrap();
    assert!(pk.get_vk().cs() == vk.cs(), "Dummy super cicuit");

    let block_trace = load_block_traces_for_test().1;
    let real_circuit = SuperCircuit::from_block_traces(block_trace).unwrap().0;

    let pk = keygen_pk2(&params, &real_circuit).unwrap();
    let vk = keygen_vk(&params, &real_circuit).unwrap();
    assert!(pk.get_vk().cs() == vk.cs(), "Real super circuit");
}

#[test]
fn test_capacity_checker() {
    init_env_and_log("integration");

    let trace_path = parse_trace_path_from_mode("multiswap");
    // let trace_path = "./tests/extra_traces/new.json";

    prepare_circuit_capacity_checker();

    let block_traces = vec![get_block_trace_from_file(trace_path)];
    let witness_block = block_traces_to_witness_block(block_traces.clone()).unwrap();

    let avg_each_tx_time = run_circuit_capacity_checker(0, 0, &block_traces, &witness_block);
    assert!(avg_each_tx_time < Duration::from_millis(100));
}

#[test]
fn estimate_circuit_rows() {
    init_env_and_log("integration");

    let (_, block_trace) = load_block_traces_for_test();

    log::info!("estimating used rows for batch");
    let rows = SuperCircuit::estimate_rows(block_trace);
    log::info!("super circuit: {:?}", rows);
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_deterministic() {
    use halo2_proofs::dev::MockProver;
    init_env_and_log("integration");
    type C = SuperCircuit;
    let block_trace = load_block_traces_for_test().1;

    let circuit1 = C::from_block_traces(block_trace.clone()).unwrap().0;
    let prover1 = MockProver::<_>::run(*INNER_DEGREE, &circuit1, circuit1.instance()).unwrap();

    let circuit2 = C::from_block_traces(block_trace).unwrap().0;
    let prover2 = MockProver::<_>::run(*INNER_DEGREE, &circuit2, circuit2.instance()).unwrap();

    let advice1 = prover1.advices();
    let advice2 = prover2.advices();
    assert_eq!(advice1.len(), advice2.len());
    for i in 0..advice1.len() {
        for j in 0..advice1[i].len() {
            if advice1[i][j] != advice2[i][j] {
                log::error!(
                    "advice assignment not same, {}th advice column, {}th row. {:?} vs {:?}",
                    i,
                    j,
                    advice1[i][j],
                    advice2[i][j]
                );
            }
        }
    }
    log::info!("test_deterministic done");
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_vk_same() {
    use halo2_proofs::dev::MockProver;
    init_env_and_log("integration");
    type C = SuperCircuit;
    let block_trace = load_block_traces_for_test().1;
    let params = load_params(PARAMS_DIR, *INNER_DEGREE, None).unwrap();

    let dummy_circuit = C::dummy_inner_circuit();
    let real_circuit = C::from_block_traces(block_trace).unwrap().0;
    let vk_empty = keygen_vk(&params, &dummy_circuit).unwrap();
    let vk_real = keygen_vk(&params, &real_circuit).unwrap();
    let vk_empty_bytes = serialize_vk(&vk_empty);
    let vk_real_bytes: Vec<_> = serialize_vk(&vk_real);

    let prover1 =
        MockProver::<_>::run(*INNER_DEGREE, &dummy_circuit, dummy_circuit.instance()).unwrap();
    let prover2 =
        MockProver::<_>::run(*INNER_DEGREE, &real_circuit, real_circuit.instance()).unwrap();

    let fixed1 = prover1.fixed();
    let fixed2 = prover2.fixed();
    assert_eq!(fixed1.len(), fixed2.len());
    for i in 0..fixed1.len() {
        for j in 0..fixed1[i].len() {
            if fixed1[i][j] != fixed2[i][j] {
                log::error!(
                    "fixed assignment not same, {}th fixed column, {}th row. {:?} vs {:?}",
                    i,
                    j,
                    fixed1[i][j],
                    fixed2[i][j]
                );
            }
        }
    }

    assert_eq!(
        vk_empty.fixed_commitments().len(),
        vk_real.fixed_commitments().len()
    );
    for i in 0..vk_empty.fixed_commitments().len() {
        if vk_empty.fixed_commitments()[i] != vk_real.fixed_commitments()[i] {
            log::error!(
                "{}th fixed_commitments not same {:?} {:?}",
                i,
                vk_empty.fixed_commitments()[i],
                vk_real.fixed_commitments()[i]
            );
        }
    }
    assert_eq!(
        vk_empty.permutation().commitments().len(),
        vk_real.permutation().commitments().len()
    );
    for i in 0..vk_empty.permutation().commitments().len() {
        if vk_empty.permutation().commitments()[i] != vk_real.permutation().commitments()[i] {
            log::error!(
                "{}th permutation_commitments not same {:?} {:?}",
                i,
                vk_empty.permutation().commitments()[i],
                vk_real.permutation().commitments()[i]
            );
        }
    }
    assert_eq!(vk_empty_bytes, vk_real_bytes);
}
