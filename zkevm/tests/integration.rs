use std::collections::HashMap;

use chrono::Utc;
use eth_types::Bytes;
use halo2_proofs::{plonk::keygen_vk, SerdeFormat};
use zkevm::{
    capacity_checker::CircuitCapacityChecker,
    circuit::{SuperCircuit, TargetCircuit, DEGREE},
    io::serialize_vk,
    prover::Prover,
    utils::{get_block_trace_from_file, load_or_create_params, load_params},
};

use test_util::{init_env_and_log, load_block_traces_for_test, PARAMS_DIR};
use zkevm::test_util;

use zkevm_circuits::util::SubCircuit;

#[ignore]
#[test]
fn test_load_params() {
    init_env_and_log();
    log::info!("start");
    load_params(
        "/home/ubuntu/scroll-zkevm/zkevm/test_params",
        26,
        SerdeFormat::RawBytesUnchecked,
    )
    .unwrap();
    load_params(
        "/home/ubuntu/scroll-zkevm/zkevm/test_params",
        26,
        SerdeFormat::RawBytes,
    )
    .unwrap();
    load_params(
        "/home/ubuntu/scroll-zkevm/zkevm/test_params.old",
        26,
        SerdeFormat::Processed,
    )
    .unwrap();
}

#[test]
fn test_capacity_checker() {
    init_env_and_log();

    let batch = vec![get_block_trace_from_file(
        "./tests/extra_traces/tx_storage_proof.json",
    )];
    log::info!("estimating circuit rows tx by tx");

    let mut checker = CircuitCapacityChecker::new();
    let results = checker.estimate_circuit_capacity(&batch);
    log::info!("after whole block: {:?}", results);

    let mut checker = CircuitCapacityChecker::new();

    for (block_idx, block) in batch.iter().enumerate() {
        for i in 0..block.transactions.len() {
            log::info!("processing {}th block {}th tx", block_idx, i);
            // the capacity_checker is expected to be used inside sequencer, where we don't have the
            // traces of blocks, instead we only have traces of tx.
            // For the "TxTrace":
            //   transactions: the tx itself. For compatibility reasons, transactions is a vector of len 1 now.
            //   execution_results: tx execution trace. Similar with above, it is also of len 1 vevtor.
            //   storage_trace:
            //     storage_trace is prestate + siblings(or proofs) of touched storage_slots and accounts of this tx.
            let mut tx_trace = block.clone();
            tx_trace.transactions = vec![tx_trace.transactions[i].clone()];
            tx_trace.execution_results = vec![tx_trace.execution_results[i].clone()];
            tx_trace.storage_trace = tx_trace.tx_storage_trace[i].clone();

            let results = checker.estimate_circuit_capacity(&[tx_trace]);
            log::info!("after {}th block {}th tx: {:?}", block_idx, i, results);
        }
    }

    log::info!("capacity_checker test done");
}

#[test]
fn estimate_circuit_rows() {
    use zkevm::circuit::{self, TargetCircuit};

    init_env_and_log();

    let (_, block_trace) = load_block_traces_for_test();

    log::info!("estimating used rows for batch");
    let rows = circuit::SuperCircuit::estimate_rows(&block_trace);
    log::info!("super circuit: {:?}", rows);
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_mock_prove() {
    use zkevm::circuit;

    use crate::test_util::load_block_traces_for_test;

    init_env_and_log();
    let block_traces = load_block_traces_for_test().1;
    Prover::mock_prove_target_circuit_batch::<circuit::SuperCircuit>(&block_traces).unwrap();
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_prove_verify() {
    test_target_circuit_prove_verify::<SuperCircuit>();
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_deterministic() {
    use halo2_proofs::dev::MockProver;
    init_env_and_log();
    type C = SuperCircuit;
    let block_trace = load_block_traces_for_test().1;

    let circuit1 = C::from_block_traces(&block_trace).unwrap().0;
    let prover1 = MockProver::<_>::run(*DEGREE as u32, &circuit1, circuit1.instance()).unwrap();

    let circuit2 = C::from_block_traces(&block_trace).unwrap().0;
    let prover2 = MockProver::<_>::run(*DEGREE as u32, &circuit2, circuit2.instance()).unwrap();

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
    init_env_and_log();
    type C = SuperCircuit;
    let block_trace = load_block_traces_for_test().1;
    let params = load_or_create_params(PARAMS_DIR, *DEGREE).unwrap();

    let dummy_circuit = C::dummy_inner_circuit();
    let real_circuit = C::from_block_traces(&block_trace).unwrap().0;
    let vk_empty = keygen_vk(&params, &dummy_circuit).unwrap();
    let vk_real = keygen_vk(&params, &real_circuit).unwrap();
    let vk_empty_bytes = serialize_vk(&vk_empty);
    let vk_real_bytes: Vec<_> = serialize_vk(&vk_real);

    let prover1 =
        MockProver::<_>::run(*DEGREE as u32, &dummy_circuit, dummy_circuit.instance()).unwrap();
    let prover2 =
        MockProver::<_>::run(*DEGREE as u32, &real_circuit, real_circuit.instance()).unwrap();

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
    use std::time::Instant;

    use zkevm::verifier::Verifier;

    init_env_and_log();

    let (_, block_traces) = load_block_traces_for_test();

    log::info!("start generating {} proof", C::name());
    let now = Instant::now();
    let mut prover = Prover::from_param_dir(PARAMS_DIR);
    let proof = prover
        .create_target_circuit_proof_batch::<C>(&block_traces)
        .unwrap();
    log::info!("finish generating proof, elapsed: {:?}", now.elapsed());

    let output_file = format!(
        "/tmp/{}_{}.json",
        C::name(),
        Utc::now().format("%Y%m%d_%H%M%S")
    );
    let mut fd = std::fs::File::create(&output_file).unwrap();
    serde_json::to_writer_pretty(&mut fd, &proof).unwrap();
    log::info!("write proof to {}", output_file);

    log::info!("start verifying proof");
    let now = Instant::now();
    let mut verifier = Verifier::from_fpath(PARAMS_DIR, None);
    assert!(verifier.verify_target_circuit_proof::<C>(&proof).is_ok());
    log::info!("finish verifying proof, elapsed: {:?}", now.elapsed());
}
