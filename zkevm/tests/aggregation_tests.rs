use halo2_proofs::poly::commitment::Params;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::CircuitExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use test_util::{create_output_dir, init, load_block_traces_for_test};
use zkevm::circuit::{SuperCircuit, TargetCircuit};
use zkevm::io::write_file;
use zkevm::prover::{Prover, TargetCircuitProof};
use zkevm::verifier::EvmVerifier;

mod mock_plonk;
mod test_util;

// An end to end integration test.
// The inner snark proofs are generated from a mock circuit
// instead of the trace files.
#[cfg(feature = "prove_verify")]
#[test]
fn test_aggregation_api() {
    std::env::set_var("VERIFY_CONFIG", "./configs/example_evm_accumulator.config");

    init();

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
    let k = 20;
    let k_agg = 26;
    let seed = [0u8; 16];
    let mut rng = XorShiftRng::from_seed(seed);

    // notice that k < k_agg which is not necessary the case in practice
    let params_outer = gen_srs(k_agg);
    let params_inner = {
        let mut params = params_outer.clone();
        params.downsize(k);
        params
    };
    log::info!("loaded parameters for degrees {} and {}", k, k_agg);

    let mut prover = Prover::from_params_and_seed(params_inner, params_outer, seed);
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
                .create_target_circuit_proof_batch::<SuperCircuit>(block_traces.as_ref(), &mut rng)
                .unwrap();

            // Dump inner circuit proof.
            proof.dump_to_file(&inner_proof_file_path).unwrap();

            proof
        });
    log::info!("got super circuit proof");

    // sanity check: the inner proof is correct

    // 3. build an aggregation circuit proof
    let agg_circuit =
        AggregationCircuit::new(&prover.agg_params, [inner_proof.snark.clone()], &mut rng);

    let proved_block_count = inner_proof.num_of_proved_blocks;
    let outer_proof = prover
        .create_agg_proof_by_agg_circuit(&agg_circuit, &mut rng, proved_block_count)
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
