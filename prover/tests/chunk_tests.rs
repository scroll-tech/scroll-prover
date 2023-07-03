use prover::{
    config::{AGG_DEGREE, CHUNK_DEGREE},
    io::{load_snark, write_file, write_snark},
    test_util::{load_block_traces_for_test, PARAMS_DIR},
    utils::{downsize_params, init_env_and_log, load_or_download_params},
    zkevm::{
        circuit::{SuperCircuit, TargetCircuit},
        Prover,
    },
    EvmVerifier,
};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use snark_verifier_sdk::{AggregationCircuit, CircuitExt};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

#[cfg(feature = "prove_verify")]
#[test]
fn test_chunk_prove_verify() {
    std::env::set_var("VERIFY_CONFIG", "./configs/verify_circuit.config");

    let output_dir = init_env_and_log("chunk_tests");
    let mut output_path = PathBuf::from_str(&output_dir).unwrap();
    log::info!("Inited ENV and created output-dir {output_dir}");

    let block_traces = load_block_traces_for_test().1;
    log::info!("Loaded block-traces");

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

    let mut params = load_or_download_params(PARAMS_DIR, *AGG_DEGREE).unwrap();
    downsize_params(&mut params, *CHUNK_DEGREE);
    let mut prover = Prover::from_params(params);
    log::info!("build prover");

    //
    // 2. read inner circuit proofs (a.k.a. SNARKs) from previous dumped file or
    //    convert block traces into
    //
    let inner_snark_file_path = format!("{}/{}_snark.json", output_dir, SuperCircuit::name());
    let inner_snark = load_snark(&inner_snark_file_path)
        .unwrap()
        .unwrap_or_else(|| {
            let snark = prover
                .gen_inner_snark::<SuperCircuit>(block_traces.as_slice())
                .unwrap();

            // Dump inner circuit proof.
            write_snark(&inner_snark_file_path, &snark);

            snark
        });
    log::info!("got super circuit proof");

    // sanity check: the inner proof is correct

    // 3. build an aggregation circuit proof
    let agg_circuit = AggregationCircuit::new(
        &prover.agg_params,
        vec![inner_snark.clone()],
        XorShiftRng::from_seed([0u8; 16]),
    );

    let chunk_proof = prover.gen_agg_evm_proof(vec![inner_snark]).unwrap();

    // Dump aggregation proof, vk and instance.
    chunk_proof.dump(&mut output_path, &"chunk").unwrap();

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
    EvmVerifier::new(deployment_code).verify(agg_circuit.instances(), chunk_proof.proof().to_vec());
    log::info!("end to end test completed");
}
