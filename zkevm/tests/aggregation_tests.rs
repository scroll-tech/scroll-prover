use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::CircuitExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use test_util::{create_output_dir, init_env_and_log, load_block_traces_for_test};
use zkevm::circuit::{SuperCircuit, TargetCircuit};
use zkevm::circuit::{AGG_DEGREE, DEGREE};
use zkevm::io::write_file;
use zkevm::prover::{Prover, TargetCircuitProof};
use zkevm::test_util::{self, PARAMS_DIR};
use zkevm::utils::load_or_create_params;
use zkevm::verifier::EvmVerifier;

// An end to end integration test.
// The inner snark proofs are generated from a mock circuit
// instead of the trace files.
#[cfg(feature = "prove_verify")]
#[test]
fn test_aggregation_api() {
    std::env::set_var("VERIFY_CONFIG", "./configs/verify_circuit.config");

    init_env_and_log();

    let output_dir = create_output_dir();
    let mut output_path = PathBuf::from_str(&output_dir).unwrap();
    log::info!("created output dir {}", output_dir);

    let block_traces = load_block_traces_for_test().1;
    log::info!("loaded block trace");

    // ====================================================
    // A whole aggregation procedure takes the following steps
    // 1. instantiation the parameters and the prover
    // 2. read inner circuit proofs (a.k.a. SNARKs) from previous dumped file or
    //    convert block traces into
    // 3. build an aggregation circuit proof
    // 4. generate bytecode for evm to verify aggregation circuit proof
    // 5. validate the proof with evm bytecode
    // ====================================================
    //
    // 1. instantiation the parameters and the prover
    //

    let params = load_or_create_params(PARAMS_DIR, *AGG_DEGREE).unwrap();
    let mut prover = Prover::from_params(params);
    log::info!("build prover");

    //
    // 2. read inner circuit proofs (a.k.a. SNARKs) from previous dumped file or
    //    convert block traces into
    //
    let inner_proof_file_path = format!("{}/{}_proof.json", output_dir, SuperCircuit::name());
    let inner_proof = TargetCircuitProof::restore_from_file(&inner_proof_file_path)
        .unwrap()
        .unwrap_or_else(|| {
            let proof = prover
                .create_target_circuit_proof_batch::<SuperCircuit>(block_traces.as_ref())
                .unwrap();

            // Dump inner circuit proof.
            proof.dump_to_file(&inner_proof_file_path).unwrap();

            proof
        });
    log::info!("got super circuit proof");

    // sanity check: the inner proof is correct

    // 3. build an aggregation circuit proof
    let agg_circuit = AggregationCircuit::new(
        &prover.agg_params,
        [inner_proof.snark.clone()],
        XorShiftRng::from_seed([0u8; 16]),
    );

    let proved_block_count = inner_proof.num_of_proved_blocks;
    let outer_proof = prover
        .create_agg_proof_by_agg_circuit(&agg_circuit, proved_block_count)
        .unwrap();

    // Dump aggregation proof, vk and instance.
    outer_proof.dump(&mut output_path).unwrap();

    log::info!("finished aggregation generation");

    // 4. generate bytecode for evm to verify aggregation circuit proof
    let agg_vk = prover.agg_pk.as_ref().unwrap().get_vk();

    // Create bytecode and dump yul-code.
    let yul_file_path = format!("{}/verifier.yul", output_dir);
    let deployment_code =
        prover.create_evm_verifier_bytecode(&agg_circuit, agg_vk, Some(Path::new(&yul_file_path)));

    // Dump bytecode.
    write_file(&mut output_path, "verifier.bin", &deployment_code);

    log::info!("finished byte code generation");

    // 5. validate the proof with evm bytecode
    EvmVerifier::new(deployment_code).verify(agg_circuit.instances(), outer_proof.proof);
    log::info!("end to end test completed");
}
