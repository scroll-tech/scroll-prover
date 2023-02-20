use std::vec;

use chrono::Utc;
use halo2_proofs::plonk::keygen_vk;
use types::eth::BlockTrace;
use zkevm::{
    circuit::{SuperCircuit, TargetCircuit, DEGREE},
    io::serialize_vk,
    prover::Prover,
    utils::{get_block_trace_from_file, load_or_create_params, read_env_var},
};

mod test_util;
use test_util::{
    init, load_block_traces_for_test, parse_trace_path_from_mode, CIRCUIT, PARAMS_DIR, SEED_PATH,
};

#[test]
fn estimate_circuit_rows() {
    use zkevm::circuit::{self, TargetCircuit};

    init();

    let (_, block_trace) = load_block_traces_for_test();

    log::info!("estimating used rows for batch");
    for circuit in CIRCUIT.split(",") {
        let rows = match circuit {
            "evm" => circuit::EvmCircuit::estimate_rows(&block_trace),
            "state" => circuit::StateCircuit::estimate_rows(&block_trace),
            "zktrie" => circuit::ZktrieCircuit::estimate_rows(&block_trace),
            "poseidon" => circuit::PoseidonCircuit::estimate_rows(&block_trace),
            "super" => circuit::SuperCircuit::estimate_rows(&block_trace),
            _ => {
                log::error!("invalid circuit: {:?}", circuit);
                0
            }
        };
        log::info!("{} circuit: {}", circuit, rows);
    }
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_mock_prove() {
    use zkevm::circuit::{
        self, EvmCircuit, PoseidonCircuit, StateCircuit, SuperCircuit, TargetCircuit, ZktrieCircuit,
    };

    use crate::test_util::load_block_traces_for_test;

    init();
    let block_traces = load_block_traces_for_test().1;

    for circuit in CIRCUIT.split(",") {
        match circuit {
            "evm" => {
                Prover::mock_prove_target_circuit_batch::<circuit::EvmCircuit>(&block_traces, true)
                    .unwrap()
            }
            "state" => Prover::mock_prove_target_circuit_batch::<circuit::StateCircuit>(
                &block_traces,
                true,
            )
            .unwrap(),
            "zktrie" => Prover::mock_prove_target_circuit_batch::<circuit::ZktrieCircuit>(
                &block_traces,
                true,
            )
            .unwrap(),
            "poseidon" => Prover::mock_prove_target_circuit_batch::<circuit::PoseidonCircuit>(
                &block_traces,
                true,
            )
            .unwrap(),
            "super" => Prover::mock_prove_target_circuit_batch::<circuit::SuperCircuit>(
                &block_traces,
                true,
            )
            .unwrap(),
            _ => {
                log::error!("invalid circuit, skip: {:?}", circuit);
            }
        };
    }
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_prove_verify() {
    use zkevm::circuit::{self, TargetCircuit};
    for circuit in CIRCUIT.split(",") {
        match circuit {
            "evm" => test_target_circuit_prove_verify::<circuit::EvmCircuit>(),
            "state" => test_target_circuit_prove_verify::<circuit::StateCircuit>(),
            "zktrie" => test_target_circuit_prove_verify::<circuit::ZktrieCircuit>(),
            "poseidon" => test_target_circuit_prove_verify::<circuit::PoseidonCircuit>(),
            "super" => test_target_circuit_prove_verify::<circuit::SuperCircuit>(),
            _ => {
                log::error!("invalid circuit, skip: {:?}", circuit);
            }
        };
    }
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_vk_same() {
    init();
    //type C = EvmCircuit;
    type C = SuperCircuit;
    let block_trace = load_block_traces_for_test().1;
    let params = load_or_create_params(PARAMS_DIR, *DEGREE).unwrap();
    let vk_empty = keygen_vk(&params, &C::empty()).unwrap();
    let vk_empty_bytes = serialize_vk(&vk_empty);
    let vk_real = keygen_vk(&params, &C::from_block_traces(&block_trace).unwrap().0).unwrap();
    let vk_real_bytes: Vec<_> = serialize_vk(&vk_real);
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

    init();

    let (_, block_traces) = load_block_traces_for_test();

    log::info!("start generating {} proof", C::name());
    let now = Instant::now();
    let mut prover = Prover::from_fpath(PARAMS_DIR, SEED_PATH);
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
