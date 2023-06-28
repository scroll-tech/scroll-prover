use halo2_proofs::poly::commitment::Params;
use mock_plonk::{MockPlonkCircuit, StandardPlonk};
use prover::{
    test_util,
    utils::init_env_and_log,
    zkevm::{Prover, Verifier},
    EvmVerifier,
};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use snark_verifier_sdk::{
    evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk, gen_pk, gen_snark_shplonk,
    AggregationCircuit, CircuitExt,
};
use test_util::mock_plonk;

// This is essentially a same test as snark-verifier/evm-verifier
#[cfg(feature = "prove_verify")]
#[test]
fn test_snark_verifier_sdk_api() {
    use prover::utils::load_or_download_params;

    use crate::test_util::PARAMS_DIR;

    std::env::set_var("VERIFY_CONFIG", "./configs/verify_circuit.config");
    let k = 8;
    let k_agg = 21;

    init_env_and_log("snark_verifier_api");

    let mut rng = XorShiftRng::from_seed([0u8; 16]);

    let circuit = StandardPlonk::rand(&mut rng);
    let params_outer = load_or_download_params(PARAMS_DIR, k_agg).unwrap();
    let params_inner = {
        let mut params = params_outer.clone();
        params.downsize(k);
        params
    };
    let pk_inner = gen_pk(&params_inner, &circuit, None);
    let snarks = (0..3)
        .map(|_| {
            gen_snark_shplonk(
                &params_inner,
                &pk_inner,
                circuit.clone(),
                &mut rng,
                None::<String>,
            )
        })
        .collect::<Vec<_>>();
    println!("finished snark generation");

    let agg_circuit = AggregationCircuit::new(&params_outer, snarks, &mut rng);
    let pk_outer = gen_pk(&params_outer, &agg_circuit, None);
    println!("finished outer pk generation");
    let instances = agg_circuit.instances();
    let proof = gen_evm_proof_shplonk(
        &params_outer,
        &pk_outer,
        agg_circuit.clone(),
        instances.clone(),
        &mut rng,
    );
    println!("finished aggregation generation");

    let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
        &params_outer,
        pk_outer.get_vk(),
        agg_circuit.num_instance(),
        None,
    );

    println!("finished bytecode generation");
    evm_verify(deployment_code, instances, proof)
}

// // A partial integration test.
// // The inner snark proofs are generated from a mock circuit
// // instead of the trace files.
// #[cfg(feature = "prove_verify")]
// #[test]
// fn test_partial_aggregation_api() {
//     use prover::utils::load_or_download_params;

//     use crate::test_util::PARAMS_DIR;

//     std::env::set_var("VERIFY_CONFIG", "./configs/verify_circuit.config");

//     init_env_and_log("snark_verifier_api");
//     let num_snarks = 3;

//     // ====================================================
//     // A whole aggregation procedure takes the following steps
//     // 1. instantiation the parameters and the prover
//     // 2. convert block traces into inner circuit proofs, a.k.a. SNARKs
//     // 3. build an aggregation circuit proof
//     // 4. generate bytecode for evm to verify aggregation circuit proof
//     // 5. validate the proof with evm bytecode
//     // ====================================================
//     //
//     // 1. instantiation the parameters and the prover
//     //
//     let k = 8;
//     let k_agg = 23;
//     let seed = [0u8; 16];
//     let mut rng = XorShiftRng::from_seed(seed);

//     // notice that k < k_agg which is not necessary the case in practice
//     let params_outer = load_or_download_params(PARAMS_DIR, k_agg).unwrap();
//     let params_inner = {
//         let mut params = params_outer.clone();
//         params.downsize(k);
//         params
//     };
//     log::info!("loaded parameters for degrees {} and {}", k, k_agg);
//     let circuit = StandardPlonk::rand(&mut rng);
//     let mut prover = Prover::from_params(params_outer.clone());
//     //
//     // 2. convert block traces into inner circuit proofs, a.k.a. SNARKs
//     //
//     // Note:
//     // we do not have traces for testing so here we simply assume that we have already
//     // obtained 3 inner circuits proofs for some dummy circuit
//     let target_circuit_proof = (0..num_snarks)
//         .map(|_| {
//             prover
//                 .gen_inner_proof::<MockPlonkCircuit>(
//                     circuit,
//                     circuit.instances(),
//                     &mut rng,
//                     0,
//                     0,
//                 )
//                 .unwrap()
//         })
//         .collect::<Vec<_>>();
//     log::info!("finished inner circuit snark generation");

//     // sanity check: the inner proof is correct
//     let mut verifier = Verifier::new(params_inner, params_outer.clone(), None);
//     for i in 0..num_snarks {
//         verifier
//             .verify_target_circuit_proof::<MockPlonkCircuit>(&target_circuit_proof[i])
//             .unwrap();
//     }
//     log::info!("sanity check: inner circuit snark are correct");

//     // 3. build an aggregation circuit proof
//     let snarks = target_circuit_proof
//         .iter()
//         .map(|p| p.snark.clone())
//         .collect::<Vec<_>>();
//     let agg_circuit = AggregationCircuit::new(&params_outer, snarks, &mut rng);
//     let pk_outer = gen_pk(&params_outer, &agg_circuit, None);

//     let instances = agg_circuit.instances();
//     let proof = gen_evm_proof_shplonk(
//         &params_outer,
//         &pk_outer,
//         agg_circuit.clone(),
//         instances.clone(),
//         &mut rng,
//     );
//     log::info!("finished aggregation generation");

//     // 4. generate bytecode for evm to verify aggregation circuit proof
//     let deployment_code =
//         prover.create_evm_verifier_bytecode(&agg_circuit, pk_outer.get_vk(), None);
//     log::info!("finished byte code generation");

//     // 5. validate the proof with evm bytecode
//     EvmVerifier::new(deployment_code).verify(instances, proof);
//     log::info!("end to end test completed");
// }
