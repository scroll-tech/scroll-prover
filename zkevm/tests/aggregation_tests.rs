use halo2_proofs::poly::commitment::Params;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::evm::gen_evm_proof_shplonk;
use snark_verifier_sdk::gen_pk;
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::CircuitExt;
use test_util::create_output_dir;
use test_util::init;
use test_util::load_block_traces_for_test;
use zkevm::circuit::SuperCircuit;
use zkevm::prover::Prover;
use zkevm::verifier::Verifier;

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

    let mut prover = Prover::from_params_and_seed(params_inner, params_outer.clone(), seed);
    prover.debug_dir = output_dir;

    log::info!("build prover");

    //
    // 2. read inner circuit proofs (a.k.a. SNARKs) from previous dumped file or
    //    convert block traces into
    //
    let super_circuit_proof = prover
        .read_target_circuit_proof_from_file()
        .unwrap()
        .unwrap_or_else(|| {
            log::info!("build super circuit from block traces");
            prover
                .create_target_circuit_proof_batch::<SuperCircuit>(block_traces.as_ref(), &mut rng)
                .unwrap()
        });

    log::info!("got super circuit proof");

    // sanity check: the inner proof is correct

    // 3. build an aggregation circuit proof
    let agg_circuit =
        AggregationCircuit::new(&params_outer, [super_circuit_proof.snark.clone()], &mut rng);
    let pk_outer = gen_pk(&params_outer, &agg_circuit, None);

    let instances = agg_circuit.instances();
    let proof = gen_evm_proof_shplonk(
        &params_outer,
        &pk_outer,
        agg_circuit.clone(),
        instances.clone(),
        &mut rng,
    );
    log::info!("finished aggregation generation");

    // 4. generate bytecode for evm to verify aggregation circuit proof
    let deployment_code = prover.create_evm_verifier_bytecode(&agg_circuit, pk_outer.get_vk());
    log::info!("finished byte code generation");

    // 5. validate the proof with evm bytecode
    Verifier::evm_verify(deployment_code, instances, proof);
    log::info!("end to end test completed");
}
