use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::plonk::VerifyingKey;

use halo2_snark_aggregator_circuit::verify_circuit::Halo2VerifierCircuit;
use halo2_snark_aggregator_solidity::MultiCircuitSolidityGenerate;
use std::fs::{self};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use zkevm::circuit::{
    EvmCircuit, PoseidonCircuit, StateCircuit, ZktrieCircuit, AGG_DEGREE, DEGREE,
};
use zkevm::prover::{AggCircuitProof, ProvedCircuit};
use zkevm::utils::{get_block_result_from_file, load_or_create_params, load_seed};
use zkevm::verifier::Verifier;
use zkevm::{io::*, prover::Prover};

mod test_util;
use test_util::{init, parse_trace_path_from_mode, PARAMS_DIR, SEED_PATH};

fn verifier_circuit_prove(output_dir: &str, mode: &str) {
    log::info!("start verifier_circuit_prove, output_dir {}", output_dir);
    let mut out_dir = PathBuf::from_str(output_dir).unwrap();

    let params = load_or_create_params(PARAMS_DIR, *DEGREE).expect("failed to init params");
    let agg_params = load_or_create_params(PARAMS_DIR, *AGG_DEGREE).expect("failed to init params");
    let seed = load_seed(SEED_PATH).expect("failed to init rng");

    let mut prover = Prover::from_params_and_seed(params.clone(), agg_params.clone(), seed);
    prover.debug_dir = output_dir.to_string();

    // auto load target proofs
    let load = Path::new(&format!("{}/zktrie_proof.json", output_dir)).exists();
    let circuit_results: Vec<ProvedCircuit> = if load {
        let mut v = Verifier::from_params(params, agg_params, None);
        log::info!("loading cached target proofs");
        vec![
            prover
                .debug_load_proved_circuit::<EvmCircuit>(Some(&mut v))
                .unwrap(),
            prover
                .debug_load_proved_circuit::<StateCircuit>(Some(&mut v))
                .unwrap(),
            prover
                .debug_load_proved_circuit::<PoseidonCircuit>(Some(&mut v))
                .unwrap(),
            prover
                .debug_load_proved_circuit::<ZktrieCircuit>(Some(&mut v))
                .unwrap(),
        ]
    } else {
        let block_results = if mode == "PACK" {
            let mut block_results = Vec::new();
            for block_number in 1..=15 {
                let trace_path = format!("tests/traces/bridge/{:02}.json", block_number);
                let block_result = get_block_result_from_file(trace_path);
                block_results.push(block_result);
            }
            block_results
        } else {
            let trace_path = parse_trace_path_from_mode(mode);
            vec![get_block_result_from_file(trace_path)]
        };
        vec![
            prover.prove_circuit::<EvmCircuit>(&block_results).unwrap(),
            prover
                .prove_circuit::<StateCircuit>(&block_results)
                .unwrap(),
            prover
                .prove_circuit::<PoseidonCircuit>(&block_results)
                .unwrap(),
            prover
                .prove_circuit::<ZktrieCircuit>(&block_results)
                .unwrap(),
        ]
    };

    let agg_proof = prover
        .create_agg_circuit_proof_impl(circuit_results)
        .unwrap();
    agg_proof.write_to_dir(&mut out_dir);
    let sol = prover.create_solidity_verifier(&agg_proof);
    write_file(
        &mut out_dir,
        "verifier2.sol",
        &Vec::<u8>::from(sol.as_bytes()),
    );
    log::info!("output files to {}", output_dir);
}

fn verifier_circuit_generate_solidity(dir: &str) {
    let mut folder = PathBuf::from_str(dir).unwrap();

    let params = load_or_create_params(PARAMS_DIR, *AGG_DEGREE).unwrap();
    let load_full = true;
    let (vk, proof, instance) = if load_full {
        let file = fs::File::open(&format!("{}/full_proof.data", dir)).unwrap();
        let agg_proof: AggCircuitProof = serde_json::from_reader(file).unwrap();
        (agg_proof.vk, agg_proof.proof, agg_proof.instance)
    } else {
        (
            load_verify_circuit_vk(&mut folder),
            load_verify_circuit_proof(&mut folder),
            load_verify_circuit_instance(&mut folder),
        )
    };
    let vk = VerifyingKey::<G1Affine>::read::<_, Halo2VerifierCircuit<'_, Bn256>, Bn256, _>(
        &mut Cursor::new(&vk),
        &params,
    )
    .unwrap();
    let request = MultiCircuitSolidityGenerate {
        verify_vk: &vk,
        verify_params: &params,
        verify_circuit_instance: load_instances(&instance),
        proof,
        verify_public_inputs_size: 4,
    };
    let sol = request.call("".into());
    write_verify_circuit_solidity(&mut folder, &Vec::<u8>::from(sol.as_bytes()));
    log::info!("write to {}/verifier.sol", dir);
}

#[cfg(feature = "prove_verify")]
#[test]
fn verifier_circuit_verify_proof() {
    init();
    use zkevm::utils::read_env_var;

    let proof = read_env_var("PROOF_JSON", "proof.json".to_string());
    let file = fs::File::open(proof).unwrap();
    let agg_proof: AggCircuitProof = serde_json::from_reader(file).unwrap();
    let verifier = Verifier::from_fpath(PARAMS_DIR, None);
    assert!(verifier.verify_agg_circuit_proof(agg_proof).is_ok())
}

fn verifier_circuit_verify(d: &str) {
    log::info!("start verifier_circuit_verify");
    let mut folder = PathBuf::from_str(d).unwrap();

    let vk = load_verify_circuit_vk(&mut folder);
    let verifier = Verifier::from_fpath(PARAMS_DIR, Some(vk.clone()));

    let proof = load_verify_circuit_proof(&mut folder);
    let instance = load_verify_circuit_instance(&mut folder);

    let agg_proof = AggCircuitProof {
        proof,
        instance,
        final_pair: vec![], // not used
        vk,
    };
    verifier.verify_agg_circuit_proof(agg_proof).unwrap();
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_4in1() {
    use chrono::Utc;
    use zkevm::utils::read_env_var;

    init();
    let exp_name = read_env_var("EXP", "".to_string());
    let mode = read_env_var("MODE", "greeter".to_string());
    let output = if exp_name.is_empty() {
        format!("output_{}_{}", Utc::now().format("%Y%m%d_%H%M%S"), mode)
    } else {
        exp_name
    };
    log::info!("output dir {}", output);
    {
        let output_dir = PathBuf::from_str(&output).unwrap();
        fs::create_dir_all(output_dir).unwrap();
    }

    verifier_circuit_prove(&output, &mode);
    verifier_circuit_verify(&output);
    verifier_circuit_generate_solidity(&output);
}
