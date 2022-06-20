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
    

    
    use halo2_proofs::{
        dev::MockProver,
        pairing::bn256::{Bn256, Fr, G1Affine},
        transcript::{
            Challenge255, PoseidonRead,
            TranscriptRead,
        },
    };
    use halo2_snark_aggregator_circuit::verify_circuit::{
        calc_verify_circuit_instances, verify_circuit_builder, Halo2VerifierCircuit,
    };

    use halo2_proofs::plonk::VerifyingKey;
    
    use zkevm::circuit::DEGREE;

    dotenv::dotenv().ok();
    init();

    log::info!("loading setup params");
    let params = load_or_create_params(PARAMS_PATH, *DEGREE).unwrap();
    let _ = load_or_create_seed(SEED_PATH).unwrap();



    #[derive(Clone)]
    struct CircuitResult {
        proof: Vec<u8>,
        vk: VerifyingKey<G1Affine>,
        instance: Vec<Vec<Vec<Fr>>>,
    }

    //struct VerifierResult {
    //    circuit: Halo2VerifierCircuit<
    //}
    let profile = |name: &str, cs: Vec<CircuitResult>| {
        // TODO: be careful here

        let target_circuit_params_verifier = params.verifier::<Bn256>(0).unwrap();

        let circuits_instances: Vec<_> = cs.iter().map(|x| x.instance.clone()).collect();
        let circuits_proofs: Vec<_> = cs.iter().map(|x| x.proof.clone()).collect();
        let circuits_vks: Vec<_> = cs.iter().map(|x| x.vk.clone()).collect();

        let instances = calc_verify_circuit_instances(
            &target_circuit_params_verifier,
            &circuits_vks,
            circuits_instances.clone(),
            circuits_proofs.clone(),
        );
        //let instances_clone = instances.clone();
        log::info!("{} calc_verify_circuit_instances done", name);
        let verify_circuit: Halo2VerifierCircuit<'_, Bn256> = verify_circuit_builder(
            &target_circuit_params_verifier,
            circuits_vks,
            &circuits_instances,
            &circuits_proofs,
            circuits_proofs.len(),
        );
        log::info!("{} create mock prover", name);
        let prover = MockProver::<Fr>::run(26, &verify_circuit, vec![instances]).unwrap();
        log::info!("{} start mock prover verify", name);
        prover.verify().unwrap();
        log::info!("{} Mock proving of verify_circuit done", name);
    };
    /* 
    let evm_circuit_r = CircuitResult {
        proof: evm_proof,
        vk: verifier.evm_vk,
        instance: vec![Default::default()],
    };
    let state_circuit_r = CircuitResult {
        proof: state_proof,
        vk: verifier.state_vk,
        instance: vec![Default::default()],
    };
    let profile_state = true;
    let profile_evm = true;
    let profile_both = true;
    */
    //if profile_state {
    //    profile("state_circuit", vec![state_circuit_r.clone()]);
    //}
    //if profile_evm {
    //    profile("evm_circuit", vec![evm_circuit_r.clone()]);
    //}
    //if profile_both {
    //    profile("both", vec![evm_circuit_r, state_circuit_r]);
    //}

    // poseidon hash
    let params8 = Params::<G1Affine>::unsafe_setup::<Bn256>(8);
    {
        let message1 = [
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
        ];
        let message2 = [
            Fr::from_str_vartime("0").unwrap(),
            Fr::from_str_vartime("1").unwrap(),
        ];
    
        let k = 8;
        let circuit = halo2_mpt_circuit::hash::HashCircuit::<3> {
            inputs: [Some(message1), Some(message2), None],
        };

        let vk = keygen_vk(&params8, &circuit).unwrap();
        let pk = keygen_pk(params8, vk, &circuit);

        let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);

        create_proof(
            params8,
            pk,
            &[circuit],
            &[&[]],
            OsRng
            &mut transcript,
        )?;

        let poseidon_circuit_r = CircuitResult {
            proof: transcript.finalize(),
            vk: pk.get_vk().clone(),
            instance: vec![Default::default()],
        };
        profile("poseidon_circuit", vec![poseidon_circuit_r.clone()]);
    }

    {
    
        let k = 8;
        let circuit = halo2_mpt_circuit::EthTrie::<Fr>::new(200);

        let vk = keygen_vk(&params8, &circuit).unwrap();
        let pk = keygen_pk(params8, vk, &circuit);

        let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);

        create_proof(
            params8,
            pk,
            &[circuit],
            &[&[]],
            OsRng
            &mut transcript,
        )?;

        let zktrie_circuit_r = CircuitResult {
            proof: transcript.finalize(),
            vk: pk.get_vk().clone(),
            instance: vec![Default::default()],
        };
        profile("zktrie_circuit", vec![zktrie_circuit_r.clone()]);
    }

/* 
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
*/
    /*
    log::info!("proving with real prover");
    log::info!("setup");

    let verify_circuit_params = load_or_create_params("params26", 26).unwrap();

    let (verify_circuit, instances) =
        build_verifier_circuit("final", vec![state_circuit_r, evm_circuit_r]);

    let LIMBS = 4;
    let verify_circuit_params_verifier =
        verify_circuit_params.verifier::<Bn256>(LIMBS * 4).unwrap();
    log::info!("setup done");
    let verify_circuit_vk =
        keygen_vk(&verify_circuit_params, &verify_circuit).expect("keygen_vk should not fail");
    log::info!("vk done");

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
        for k in [26, 25, 24, 23, 22, 21, 20, 19, 18] {
            log::info!("create mock prover {}", k);
            match MockProver::<Fr>::run(k, &verify_circuit2, vec![instances2.clone()]) {
                Ok(prover) => {
                    log::info!("start mock prover verify");
                    let r = prover.verify();
                    log::info!("Mock proving of verify_circuit done {} {:?}", k, r);
                }
                Err(e) => {
                    log::info!("err {:?} {}", e, k);
                }
            }
        }
    }
    */
}
