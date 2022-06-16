use std::sync::Once;
use std::time::Instant;
use zkevm::prover::Prover;
use zkevm::utils::{get_block_result_from_file, load_or_create_params, load_or_create_seed};
use zkevm::verifier::Verifier;

const PARAMS_PATH: &str = "./test_params";
const SEED_PATH: &str = "./test_seed";
static ENV_LOGGER: Once = Once::new();

fn parse_trace_path_from_env(mode: &str) -> &'static str {
    let trace_path = match mode {
        "empty" => "./tests/trace-empty.json",
        "greeter" => "./tests/trace-greeter.json",
        "multiple" => "./tests/trace-multiple-erc20.json",
        "native" => "./tests/trace-native-transfer.json",
        "single" => "./tests/trace-single-erc20.json",
        _ => "./tests/trace-multiple-erc20.json",
    };
    log::info!("using mode {:?}, testing with {:?}", mode, trace_path);
    trace_path
}

fn init() {
    ENV_LOGGER.call_once(env_logger::init);
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_evm_prove_verify() {
    use zkevm::{circuit::DEGREE, utils::read_env_var};

    dotenv::dotenv().ok();
    init();
    let trace_path = parse_trace_path_from_env(&read_env_var("MODE", "multiple".to_string()));

    let _ = load_or_create_params(PARAMS_PATH, *DEGREE).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let block_result = get_block_result_from_file(trace_path);

    log::info!("start generating evm_circuit proof");
    let now = Instant::now();
    let prover = Prover::from_fpath(PARAMS_PATH, SEED_PATH);
    let proof = prover.create_evm_proof(&block_result).unwrap();
    log::info!(
        "finish generating evm_circuit proof, cost {:?}",
        now.elapsed()
    );

    log::info!("start verifying evm_circuit proof");
    let now = Instant::now();
    let verifier = Verifier::from_fpath(PARAMS_PATH);
    log::info!(
        "finish verifying evm_circuit proof, cost {:?}",
        now.elapsed()
    );
    assert!(verifier.verify_evm_proof(proof, &block_result));
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_state_prove_verify() {
    use zkevm::{circuit::DEGREE, utils::read_env_var};

    dotenv::dotenv().ok();
    init();
    let trace_path = parse_trace_path_from_env(&read_env_var("MODE", "multiple".to_string()));

    let _ = load_or_create_params(PARAMS_PATH, *DEGREE).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let block_result = get_block_result_from_file(trace_path);

    log::info!("start generating state_circuit proof");
    let now = Instant::now();
    let prover = Prover::from_fpath(PARAMS_PATH, SEED_PATH);
    let proof = prover.create_state_proof(&block_result).unwrap();
    log::info!(
        "finish generating state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start verifying state_circuit proof");
    let now = Instant::now();
    let verifier = Verifier::from_fpath(PARAMS_PATH);
    log::info!(
        "finish verifying state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );
    assert!(verifier.verify_state_proof(proof, &block_result));
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_state_evm_connect() {
    use std::fs;

    use eth_types::Field;
    use halo2_proofs::{
        dev::MockProver,
        pairing::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, PoseidonRead, PoseidonWrite, TranscriptRead, self,
        },
    };
    use halo2_snark_aggregator_circuit::verify_circuit::{
        self, calc_verify_circuit_instances, verify_circuit_builder, Halo2VerifierCircuit,
        SingleProofWitness,
    };
    use rand::rngs::OsRng;
    use zkevm::circuit::DEGREE;

    dotenv::dotenv().ok();
    init();

    log::info!("loading setup params");
    let params = load_or_create_params(PARAMS_PATH, *DEGREE).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();

    let trace_path = parse_trace_path_from_env("greeter");
    let block_result = get_block_result_from_file(trace_path);

    let prover = Prover::from_fpath(PARAMS_PATH, SEED_PATH);
    let verifier = Verifier::from_fpath(PARAMS_PATH);

    log::info!("start generating state_circuit proof");
    let now = Instant::now();
    let state_proof = prover.create_state_proof(&block_result).unwrap();
    log::info!(
        "finish generating state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start verifying state_circuit proof");
    let now = Instant::now();
    assert!(verifier.verify_state_proof(state_proof.clone(), &block_result));
    log::info!(
        "finish verifying state_circuit proof, elapsed: {:?}",
        now.elapsed()
    );

    log::info!("start generating evm_circuit proof");
    let now = Instant::now();
    let evm_proof = prover.create_evm_proof(&block_result).unwrap();
    log::info!(
        "finish generating evm_circuit proof, cost {:?}",
        now.elapsed()
    );

    log::info!("start verifying evm_circuit proof");
    let now = Instant::now();
    assert!(verifier.verify_evm_proof(evm_proof.clone(), &block_result));
    log::info!(
        "finish verifying evm_circuit proof, cost {:?}",
        now.elapsed()
    );

    let rw_commitment_state = {
        let mut transcript = PoseidonRead::<_, _, Challenge255<G1Affine>>::init(&state_proof[..]);
        transcript.read_point().unwrap()
    };
    log::info!("rw_commitment_state {:?}", rw_commitment_state);

    let rw_commitment_evm = {
        let mut transcript = PoseidonRead::<_, _, Challenge255<G1Affine>>::init(&evm_proof[..]);
        transcript.read_point().unwrap()
    };
    log::info!("rw_commitment_evm {:?}", rw_commitment_evm);

    assert_eq!(rw_commitment_evm, rw_commitment_state);
    log::info!("Same commitment! Test passes!");

    // test recursive
    //log::info!("start test recursive");
    let target_circuit_params_verifier = &params.verifier::<Bn256>(0).unwrap();
    //let evm_instance:  &[&[&[Field]]] = &[&[]];
    let evm_instance: Vec<Vec<Vec<Fr>>> = vec![Default::default()];
    //let state_instance:  &[&[&[Fr]]] = &[&[]];
    let state_instance: Vec<Vec<Vec<Fr>>> = vec![Default::default()];
    /*
        let circuits_instances = vec![evm_instance, state_instance];
        let circuits_proofs = vec![evm_proof, state_proof];
        let circuits_vks = vec![verifier.evm_vk, verifier.state_vk];
    */

    let circuits_instances = vec![state_instance, evm_instance];
    let circuits_proofs = vec![state_proof, evm_proof];
    let circuits_vks = vec![verifier.state_vk, verifier.evm_vk];

    let instances = calc_verify_circuit_instances(
        &target_circuit_params_verifier,
        &circuits_vks,
        circuits_instances.clone(),
        circuits_proofs.clone(),
    );

    log::info!("calc_verify_circuit_instances done ");
    let verify_circuit: Halo2VerifierCircuit<'_, Bn256> = verify_circuit_builder(
        &target_circuit_params_verifier,
        circuits_vks,
        &circuits_instances,
        &circuits_proofs,
        2,
    );
    if false {
        log::info!("create mock prover");
        let prover = MockProver::<Fr>::run(26, &verify_circuit, vec![instances.clone()]).unwrap();
        log::info!("start mock prover verify");
        prover.verify().unwrap();
        log::info!("Mock proving of verify_circuit done");
    }

    log::info!("proving with real prover");
    log::info!("setup");

    let verify_circuit_params = load_or_create_params("params26", 26).unwrap();
    
    let LIMBS = 4;
    let verify_circuit_params_verifier = verify_circuit_params.verifier::<Bn256>(LIMBS * 4).unwrap();
    log::info!("setup done");
    let verify_circuit_vk =
        keygen_vk(&verify_circuit_params, &verify_circuit).expect("keygen_vk should not fail");

    let verify_circuit_pk = keygen_pk(&verify_circuit_params, verify_circuit_vk, &verify_circuit)
        .expect("keygen_pk should not fail");

    log::info!("pk vk done");

    let mut proof2 = Vec::<u8>::new();

    if true {
        let instances_slice: &[&[&[Fr]]] = &[&[&instances[..]]];
        let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);

        create_proof(
            &verify_circuit_params,
            &verify_circuit_pk,
            &[verify_circuit],
            instances_slice,
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        proof2 = proof.clone();
        log::info!("proving done");

        let strategy = SingleVerifier::new(&verify_circuit_params_verifier);

        let mut transcript = PoseidonRead::<_, _, Challenge255<_>>::init(&proof[..]);

        let verify_circuit_vk = verify_circuit_pk.get_vk();
        verify_proof(
            &verify_circuit_params_verifier,
            &verify_circuit_vk,
            strategy,
            instances_slice,
            &mut transcript,
        )
        .expect("verify aggregate proof fail");
        log::info!("verify done");
    }
    fs::write("proof2", proof2.clone()).unwrap();
    //drop(instances_slice);
    let transcript2 = vec![proof2.clone()];
    let ii = vec![instances];
    let instances2 = vec![vec![ii]];
    let vks2 = vec![verify_circuit_pk.get_vk().clone()];
    let verify_circuit2: Halo2VerifierCircuit<'_, Bn256> = verify_circuit_builder(
        &verify_circuit_params_verifier,
        vks2.clone(),
        &instances2,
        &transcript2,
        1,
    );
    log::info!("verify_circuit2 built");

    let instances2 = calc_verify_circuit_instances(
        &verify_circuit_params_verifier,
        &vks2,
        instances2.clone(),
        transcript2.clone(),
    );

    if true {
        for k in [26,25,24,23,22,21,20,19,18] {
            log::info!("create mock prover {}", k);
            match MockProver::<Fr>::run(k, &verify_circuit2, vec![instances2.clone()]) {
                Ok(prover) => {

                    log::info!("start mock prover verify");
                    let r = prover.verify();
                    log::info!("Mock proving of verify_circuit done {} {:?}", k, r);
                },
                Err(e) => {
                    log::info!("err {:?} {}", e, k);
                }
            }
        }
    }

}
