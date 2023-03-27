use halo2_proofs::poly::commitment::Params;
use mock_plonk::MockPlonkCircuit;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::CircuitExt;
use snark_verifier_sdk::{gen_pk, halo2::gen_snark_shplonk};
use zkevm::io::serialize_vk;
use std::path::Path;
use test_util::init;
use zkevm::prover::{Prover, TargetCircuitProof};
use zkevm::verifier::Verifier;
use mock_plonk::StandardPlonk;

mod mock_plonk;
mod test_util;

// This is essentially a same test as snark-verifier/evm-verifier
#[test]
fn test_snark_verifier_sdk_api() {
    std::env::set_var("VERIFY_CONFIG", "./configs/example_evm_accumulator.config");
    let k = 8;
    let k_agg = 21;

    init();

    let mut rng = XorShiftRng::from_seed([0u8; 16]);

    let circuit = StandardPlonk::rand(&mut rng);
    let params_outer = gen_srs(k_agg);
    let params_inner = {
        let mut params = params_outer.clone();
        params.downsize(k);
        params
    };
    let pk_inner = gen_pk(&params_inner, &circuit, Some(Path::new("data/inner.pkey")));
    let snarks = (0..3)
        .map(|i| {
            gen_snark_shplonk(
                &params_inner,
                &pk_inner,
                circuit.clone(),
                &mut rng,
                Some(Path::new(&format!("data/inner_{}.snark", i).to_string())),
            )
        })
        .collect::<Vec<_>>();
    println!("finished snark generation");

    let agg_circuit = AggregationCircuit::new(&params_outer, snarks, &mut rng);
    let pk_outer = gen_pk(
        &params_outer,
        &agg_circuit,
        Some(Path::new("data/outer.pkey")),
    );
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
        Some(Path::new("data/deployed_code.sol")),
    );

    println!("finished bytecode generation");
    evm_verify(deployment_code, instances, proof)
}


// A partial integration test.
// The inner snark proofs are generated from a mock circuit 
// instead of the trace files.
#[test]
fn test_aggregation_api() {
    std::env::set_var("VERIFY_CONFIG", "./configs/example_evm_accumulator.config");

    init();
    let num_snarks = 3;
    let k = 8;
    let k_agg = 21;
    let seed = [0u8; 16];
    let mut rng = XorShiftRng::from_seed(seed);

    let circuit = StandardPlonk::rand(&mut rng);
    let params_outer = gen_srs(k_agg);
    let params_inner = {
        let mut params = params_outer.clone();
        params.downsize(k);
        params
    };

    let prover = Prover::from_params_and_seed(params_inner, params_outer, seed);

    // ====================================================
    // A whole aggregation procedure takes the following steps
    // 1. instantiation the parameters and the prover
    // 2. convert block traces into inner circuit proofs, a.k.a. SNARKs
    // 3. build an aggregation circuit proof
    // 4. generate bytecode for evm to verify aggregation circuit proof
    // 5. validate the proof with evm bytecode
    // ====================================================
    //
    // 1. instantiation the parameters and the prover
    //
    let k = 8;
    let k_agg = 21;
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

    //
    // 2. convert block traces into inner circuit proofs, a.k.a. SNARKs
    //
    // Note:
    // we do not have traces for testing so here we simply assume that we have already
    // obtained 3 inner circuits proofs for some dummy circuit
    let pk_inner = gen_pk(&params_inner, &circuit, None);
    let vk_inner = pk_inner.get_vk();
    let vk_inner_bytes = serialize_vk(vk_inner);

    let snarks = (0..num_snarks)
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
    log::info!("finished inner circuit snark generation");

    // sanity check: the inner proof is correct
    let mut verifier = Verifier::new(params_inner, params_outer.clone(), None);
    for i in 0..num_snarks {
        let proof = TargetCircuitProof {
            name: "MockPlonk".into(),
            snark: snarks[i].clone(),
            vk: vk_inner_bytes.clone(),
            num_of_proved_blocks: 0,
            total_num_of_blocks: 0,
        };
        verifier.verify_target_circuit_proof::<MockPlonkCircuit>(&proof).unwrap();
    }
    log::info!("sanity check: inner circuit snark are correct");

    // 3. build an aggregation circuit proof
    let agg_circuit = AggregationCircuit::new(&params_outer, snarks, &mut rng);
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
    let deployment_code = prover.create_evm_verifier_bytecode(
        &agg_circuit,
        pk_outer.get_vk(),
    );
    log::info!("finished byte code generation");

    // 5. validate the proof with evm bytecode
    Verifier::evm_verify(deployment_code, instances, proof);
    log::info!("end to end test completed");
}
