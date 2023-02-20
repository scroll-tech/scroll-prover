use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::plonk::VerifyingKey;

use halo2_snark_aggregator_circuit::verify_circuit::Halo2VerifierCircuit;
use halo2_snark_aggregator_solidity::MultiCircuitSolidityGenerate;
use std::fs::{self};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use zkevm::circuit::{PoseidonCircuit, SuperCircuit, ZktrieCircuit, AGG_DEGREE, DEGREE};
use zkevm::prover::{AggCircuitProof, ProvedCircuit};
use zkevm::utils::{get_block_trace_from_file, load_or_create_params, load_seed};
use zkevm::verifier::Verifier;
use zkevm::{io::*, prover::Prover};

mod test_util;
use test_util::{
    init, load_block_traces_for_test, parse_trace_path_from_mode, PARAMS_DIR, SEED_PATH,
};

fn verifier_circuit_prove(output_dir: &str) {
    log::info!("start verifier_circuit_prove, output_dir {}", output_dir);
    let mut out_dir = PathBuf::from_str(output_dir).unwrap();

    let params = load_or_create_params(PARAMS_DIR, *DEGREE).expect("failed to init params");
    let agg_params = load_or_create_params(PARAMS_DIR, *AGG_DEGREE).expect("failed to init params");
    let seed = load_seed(SEED_PATH).expect("failed to init rng");

    let mut prover = Prover::from_params_and_seed(params.clone(), agg_params.clone(), seed);
    prover.debug_dir = output_dir.to_string();

    // auto load target proofs
    let load = Path::new(&format!("{output_dir}/super_proof.json")).exists();
    let circuit_results: Vec<ProvedCircuit> = if load {
        let mut v = Verifier::from_params(params, agg_params, None);
        log::info!("loading cached target proofs");
        vec![prover
            .debug_load_proved_circuit::<SuperCircuit>(Some(&mut v))
            .unwrap()]
    } else {
        let block_traces = load_block_traces_for_test().1;
        vec![prover.prove_circuit::<SuperCircuit>(&block_traces).unwrap()]
    };

    let agg_proof = prover
        .create_agg_circuit_proof_impl(circuit_results)
        .unwrap();
    agg_proof.write_to_dir(&mut out_dir);
    log::info!("output files to {}", output_dir);
}

fn verifier_circuit_generate_solidity(dir: &str) {
    let mut folder = PathBuf::from_str(dir).unwrap();

    let params = load_or_create_params(PARAMS_DIR, *AGG_DEGREE).unwrap();
    let load_full = true;
    let (vk, proof, instance) = if load_full {
        let file = fs::File::open(format!("{dir}/full_proof.data")).unwrap();
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
        vk,
        final_pair: vec![], // not used
        block_count: 0,     // not used
    };
    verifier.verify_agg_circuit_proof(agg_proof).unwrap();
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_agg() {
    use chrono::Utc;
    use zkevm::utils::read_env_var;

    init();
    let mode = read_env_var("MODE", "multi".to_string());
    let output = read_env_var(
        "OUTPUT_DIR",
        format!("output_{}_{}", Utc::now().format("%Y%m%d_%H%M%S"), mode),
    );
    log::info!("output dir {}", output);
    let output_dir = PathBuf::from_str(&output).unwrap();
    fs::create_dir_all(output_dir).unwrap();

    verifier_circuit_prove(&output);
    verifier_circuit_verify(&output);
    verifier_circuit_generate_solidity(&output);
}
