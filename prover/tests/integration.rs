use halo2_proofs::{
    dev::MockProver,
    plonk::{keygen_pk2, keygen_vk},
    poly::commitment::Params,
};
use itertools::Itertools;
use prover::{
    config::INNER_DEGREE,
    inner::{Prover, Verifier},
    io::serialize_vk,
    test_util::{load_block_traces_for_test, parse_trace_path_from_mode, PARAMS_DIR},
    types::eth::BlockTrace,
    utils::{get_block_trace_from_file, init_env_and_log, load_params, short_git_version},
    zkevm::{
        circuit::{SuperCircuit, TargetCircuit},
        CircuitCapacityChecker,
    },
};
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
    let real_circuit = SuperCircuit::from_block_traces(&block_trace).unwrap().0;

    let pk = keygen_pk2(&params, &real_circuit).unwrap();
    let vk = keygen_vk(&params, &real_circuit).unwrap();
    assert!(pk.get_vk().cs() == vk.cs(), "Real super circuit");
}

#[test]
fn test_capacity_checker() {
    init_env_and_log("integration");
    let trace_path = parse_trace_path_from_mode("multiswap");
    //let trace_path = "./tests/extra_traces/new.json";
    let batch = vec![get_block_trace_from_file(trace_path)];

    // Force the evm_circuit::param::EXECUTION_STATE_HEIGHT_MAP be inited;
    let mulmod_height = zkevm_circuits::evm_circuit::ExecutionState::MULMOD.get_step_height();
    log::debug!("mulmod_height {mulmod_height}");
    debug_assert_eq!(mulmod_height, 18);

    log::info!(
        "estimating circuit rows tx by tx, tx num {}",
        batch[0].execution_results.len()
    );
    let mut checker = CircuitCapacityChecker::new();
    //checker.light_mode = false;
    let start_time = std::time::Instant::now();
    let mut tx_num = 0;
    for (block_idx, block) in batch.iter().enumerate() {
        for i in 0..block.transactions.len() {
            log::info!("processing {}th block {}th tx", block_idx, i);
            #[rustfmt::skip]
            /*  
            The capacity_checker is expected to be run inside sequencer, where we don't have the traces of blocks, instead we only have traces of tx.
            For the "tx_trace":
                transactions: 
                    the tx itself. For compatibility reasons, transactions is a vector of len 1 now.   
                execution_results: 
                    tx execution trace. Similar with above, it is also of len 1 vevtor.   
                storage_trace: 
                    storage_trace is prestate + siblings(or proofs) of touched storage_slots and accounts of this tx.
            */
            let tx_trace = BlockTrace {
                transactions: vec![block.transactions[i].clone()],
                execution_results: vec![block.execution_results[i].clone()],
                storage_trace: block.tx_storage_trace[i].clone(),
                chain_id: block.chain_id,
                coinbase: block.coinbase.clone(),
                header: block.header.clone(),
                start_l1_queue_index: block.start_l1_queue_index,
                tx_storage_trace: Vec::new(), // not used
            };
            log::debug!("calling estimate_circuit_capacity");
            let results = checker.estimate_circuit_capacity(&[tx_trace]);
            log::info!("after {}th block {}th tx: {:#?}", block_idx, i, results);
        }
        tx_num += block.transactions.len();
    }
    log::info!("capacity_checker test done");
    let ccc_result_tx_by_tx = checker.get_acc_row_usage(false);
    log::info!(
        "ccc result tx by tx {:#?}, after normalize {:#?}",
        ccc_result_tx_by_tx,
        ccc_result_tx_by_tx.normalize()
    );
    let avg_ccc_time = start_time.elapsed().as_millis() as usize / tx_num;
    log::info!("avg time each tx: {avg_ccc_time}ms",);
    assert!(avg_ccc_time < 50);

    for light_mode in [true, false] {
        log::info!("estimating circuit rows whole block, light_mode {light_mode}");
        let mut checker = CircuitCapacityChecker::new();
        checker.light_mode = light_mode;
        checker.estimate_circuit_capacity(&batch).unwrap();
        let ccc_result_whole_block = checker.get_acc_row_usage(false);
        log::info!(
            "ccc result whole block {:#?}, after normalize {:#?}",
            ccc_result_whole_block,
            ccc_result_whole_block.normalize()
        );

        for (t, b) in ccc_result_tx_by_tx
            .row_usage_details
            .iter()
            .zip_eq(ccc_result_whole_block.row_usage_details.iter())
        {
            log::info!(
                "{}: {}(tx) vs {}(block), over estimate ratio {}",
                t.name,
                t.row_number,
                b.row_number,
                t.row_number as f64 / b.row_number as f64
            );
            assert!(t.row_number >= b.row_number);
        }
    }
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
