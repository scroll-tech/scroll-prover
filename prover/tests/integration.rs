use halo2_proofs::{
    dev::MockProver,
    plonk::{keygen_pk2, keygen_vk},
    SerdeFormat,
};
use prover::{
    config::INNER_DEGREE,
    inner::{Prover, Verifier},
    io::serialize_vk,
    test_util::{load_block_traces_for_test, parse_trace_path_from_mode, PARAMS_DIR},
    utils::{get_block_trace_from_file, init_env_and_log, load_params},
    zkevm::{
        circuit::{block_traces_to_padding_witness_block, SuperCircuit, TargetCircuit},
        CircuitCapacityChecker,
    },
};
use zkevm_circuits::util::SubCircuit;

#[ignore]
#[test]
fn test_load_params() {
    init_env_and_log("integration");
    log::info!("start");
    load_params(
        "/home/ubuntu/scroll-prover/prover/test_params",
        26,
        Some(SerdeFormat::RawBytesUnchecked),
    )
    .unwrap();
    load_params(
        "/home/ubuntu/scroll-prover/prover/test_params",
        26,
        Some(SerdeFormat::RawBytes),
    )
    .unwrap();
    load_params(
        "/home/ubuntu/scroll-prover/prover/test_params.old",
        26,
        Some(SerdeFormat::Processed),
    )
    .unwrap();
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
    let real_circuit = SuperCircuit::from_block_traces(&block_trace).unwrap().0;

    let pk = keygen_pk2(&params, &real_circuit).unwrap();
    let vk = keygen_vk(&params, &real_circuit).unwrap();
    assert!(pk.get_vk().cs() == vk.cs(), "Real super circuit");
}

#[test]
fn test_capacity_checker() {
    init_env_and_log("integration");
    let trace_path = parse_trace_path_from_mode("multiswap");
    let batch = vec![get_block_trace_from_file(trace_path)];
    log::info!("estimating circuit rows tx by tx");

    let mut checker = CircuitCapacityChecker::new();
    let results = checker.estimate_circuit_capacity(&batch);
    log::info!("after whole block: {:?}", results);

    let mut checker = CircuitCapacityChecker::new();
    let start_time = std::time::Instant::now();
    let mut tx_num = 0;
    for (block_idx, block) in batch.iter().enumerate() {
        for i in 0..block.transactions.len() {
            log::info!("processing {}th block {}th tx", block_idx, i);
            // the capacity_checker is expected to be used inside sequencer, where we don't have the
            // traces of blocks, instead we only have traces of tx.
            // For the "TxTrace":
            //   transactions: the tx itself. For compatibility reasons, transactions is a vector of
            // len 1 now.   execution_results: tx execution trace. Similar with above,
            // it is also of len 1 vevtor.   storage_trace:
            //     storage_trace is prestate + siblings(or proofs) of touched storage_slots and
            // accounts of this tx.
            let mut tx_trace = block.clone();
            tx_trace.transactions = vec![tx_trace.transactions[i].clone()];
            tx_trace.execution_results = vec![tx_trace.execution_results[i].clone()];
            tx_trace.storage_trace = tx_trace.tx_storage_trace[i].clone();

            let results = checker.estimate_circuit_capacity(&[tx_trace]);
            log::info!("after {}th block {}th tx: {:?}", block_idx, i, results);
        }
        tx_num += block.transactions.len();
    }
    log::info!("capacity_checker test done");
    log::info!(
        "avg time each tx: {}ms",
        start_time.elapsed().as_millis() as usize / tx_num
    );
}

#[test]
fn estimate_circuit_rows() {
    init_env_and_log("integration");

    let (_, block_trace) = load_block_traces_for_test();

    log::info!("estimating used rows for batch");
    let rows = SuperCircuit::estimate_rows(&block_trace);
    log::info!("super circuit: {:?}", rows);
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_mock_prove_padding() {
    init_env_and_log("integration");
    let block_traces = load_block_traces_for_test().1;
    let witness_block = block_traces_to_padding_witness_block(&block_traces).unwrap();
    let (circuit, instance) = SuperCircuit::from_witness_block(&witness_block).unwrap();
    let prover = MockProver::<_>::run(*INNER_DEGREE, &circuit, instance).unwrap();
    if let Err(errs) = prover.verify_par() {
        log::error!("err num: {}", errs.len());
        for err in &errs {
            log::error!("{}", err);
        }
        panic!("mock prove failed");
    }
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_mock_prove() {
    init_env_and_log("integration");
    let block_traces = load_block_traces_for_test().1;
    Prover::<SuperCircuit>::mock_prove_target_circuit_batch(&block_traces).unwrap();
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_inner_prove_verify() {
    test_target_circuit_prove_verify::<SuperCircuit>();
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_deterministic() {
    use halo2_proofs::dev::MockProver;
    init_env_and_log("integration");
    type C = SuperCircuit;
    let block_trace = load_block_traces_for_test().1;

    let circuit1 = C::from_block_traces(&block_trace).unwrap().0;
    let prover1 = MockProver::<_>::run(*INNER_DEGREE, &circuit1, circuit1.instance()).unwrap();

    let circuit2 = C::from_block_traces(&block_trace).unwrap().0;
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
    let real_circuit = C::from_block_traces(&block_trace).unwrap().0;
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

fn test_target_circuit_prove_verify<C: TargetCircuit>() {
    let test_name = "inner_tests";
    let output_dir = init_env_and_log(test_name);
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let chunk_trace = load_block_traces_for_test().1;
    log::info!("Loaded chunk trace");

    let mut prover = Prover::<C>::from_params_dir(PARAMS_DIR);
    log::info!("Constructed prover");

    let proof = prover
        .load_or_gen_inner_proof(test_name, "inner", chunk_trace, Some(&output_dir))
        .unwrap();
    log::info!("Got inner snark");

    let verifier = Verifier::<C>::from_params_dir(PARAMS_DIR, None);
    assert!(verifier.verify_inner_snark(proof.to_snark()));
    log::info!("Finish inner snark verification");
}
