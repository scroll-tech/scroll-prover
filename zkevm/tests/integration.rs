use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier, VerifyingKey,
};
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, PoseidonWrite, PoseidonRead};
use halo2_snark_aggregator_circuit::verify_circuit::{
    calc_verify_circuit_instances, verify_circuit_builder, Halo2VerifierCircuit,
};
use pairing::bn256::G1Affine;
use pairing::group::ff::PrimeField;
use rand::rngs::OsRng;
use zkevm::circuit::DEGREE;
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::sync::Once;
use std::time::Instant;
use zkevm::prover::Prover;
use zkevm::utils::{get_block_result_from_file, load_or_create_params, load_or_create_seed};
use zkevm::verifier::Verifier;

use halo2_snark_aggregator_solidity::{SolidityGenerate, SolidityGenerate2};

use halo2_proofs::{
    dev::MockProver,
    pairing::bn256::{Bn256, Fr},
};

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

#[derive(Clone)]
struct CircuitResult {
    proof: Vec<u8>,
    vk: VerifyingKey<G1Affine>,
    instance: Vec<Vec<Vec<Fr>>>,
}

fn run_verifier_circuit(name: &str, params: &Params<G1Affine>, cs: Vec<CircuitResult>, real: bool) {
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
    let mock = true;
    if mock {
        log::info!("{} create mock prover", name);
        let prover = MockProver::<Fr>::run(26, &verify_circuit, vec![instances.clone()]).unwrap();
        log::info!("{} start mock prover verify", name);
        prover.verify().unwrap();
        log::info!("{} Mock proving of verify_circuit done", name);
    } 
    if real {
        log::info!("setup");
        let verify_circuit_params = load_or_create_params("params26", 26).unwrap();

        log::info!("setup done");

        let LIMBS = 4;
        let verify_circuit_params_verifier =
            verify_circuit_params.verifier::<Bn256>(LIMBS * 4).unwrap();
        let verify_circuit_vk =
            keygen_vk(&verify_circuit_params, &verify_circuit).expect("keygen_vk should not fail");
        log::info!("vk done");

        log::info!("pk done");

        if true {
            let instances_slice: &[&[&[Fr]]] = &[&[&instances[..]]];
            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

            let load_proof = false;

            let proof = if load_proof {
                let mut f = File::open("proof").unwrap();
                let mut buffer = Vec::new();

                // read the whole file
                f.read_to_end(&mut buffer).unwrap();
                buffer
            } else {
                let verify_circuit_pk = keygen_pk(
                    &verify_circuit_params,
                    verify_circuit_vk.clone(),
                    &verify_circuit,
                )
                .expect("keygen_pk should not fail");

                log::info!("proving with real prover");
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
                fs::write("proof", proof.clone()).unwrap();
                log::info!("proving done");
                proof
            };

            let strategy = SingleVerifier::new(&verify_circuit_params_verifier);

            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

            //let verify_circuit_vk = verify_circuit_pk.get_vk();
            verify_proof(
                &verify_circuit_params_verifier,
                &verify_circuit_vk,
                strategy,
                instances_slice,
                &mut transcript,
            )
            .expect("verify aggregate proof fail");
            log::info!("verify done");

            let soli_gen = true;

            if soli_gen {
                let request = SolidityGenerate2 {
                    params: verify_circuit_params_verifier,
                    verify_circuit_vk: verify_circuit_vk.clone(),
                    verify_circuit_instance: vec![vec![instances]],
                    proof: proof,
                };

                let template_folder = PathBuf::from(
                    "../../halo2-snark-aggregator/halo2-snark-aggregator-solidity/templates",
                );
                let sol = request.call(template_folder);

                fs::write("verifier.sol", sol.clone()).unwrap();
                log::info!("write to verifier.sol");
            }
        }
    }
}


fn zktrie_result(params: &Params<G1Affine>) -> CircuitResult {
    let circuit = halo2_mpt_circuits::EthTrie::<Fr>::new(10);

    let prover = MockProver::<Fr>::run(*DEGREE as u32, &circuit, vec![]).unwrap();
    log::info!("{} start mock prover verify", "zktrie");
    prover.verify().unwrap();

    log::info!("Mock proving of {} done", "zktrie");

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);

    create_proof(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript).unwrap();

    let proof = transcript.finalize();
    {
        //let public_input_len = power_of_randomness[0].len();
        let public_input_len = 0;
        let verifier_params: ParamsVerifier<Bn256> = params.verifier(public_input_len).unwrap();

        let mut transcript = PoseidonRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleVerifier::new(&verifier_params);

        let vr = verify_proof(
            &verifier_params,
            &pk.get_vk(),
            strategy,
            //&[&power_of_randomness],
            &[&[]],
            &mut transcript,
        );
        println!("vr {:#?}", vr);
        assert!(vr.is_ok());
    }

    let zktrie_circuit_r = CircuitResult {
        proof: proof,
        vk: pk.get_vk().clone(),
        instance: vec![Default::default()],
    };
    zktrie_circuit_r
}


fn poseidon_result(params: &Params<G1Affine>) -> CircuitResult {
    let message1 = [
        Fr::from_str_vartime("1").unwrap(),
        Fr::from_str_vartime("2").unwrap(),
    ];
    let message2 = [
        Fr::from_str_vartime("0").unwrap(),
        Fr::from_str_vartime("1").unwrap(),
    ];

    let circuit = halo2_mpt_circuits::hash::HashCircuit::<3> {
        inputs: [
            Some(message1),
            Some(message2),
            Some([Fr::one(), Fr::zero()]),
        ],
    };

    let prover = MockProver::<Fr>::run(*DEGREE as u32, &circuit, vec![]).unwrap();
    log::info!("{} start mock prover verify", "poseidon");
    prover.verify().unwrap();

    log::info!("Mock proving of {} done", "poseidon");

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);

    create_proof(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript).unwrap();

    let poseidon_circuit_r = CircuitResult {
        proof: transcript.finalize(),
        vk: pk.get_vk().clone(),
        instance: vec![Default::default()],
    };
    poseidon_circuit_r
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_connect() {
    use std::fs;

    use halo2_proofs::{
        dev::MockProver,
        pairing::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, SingleVerifier},
        poly::commitment::{Params, ParamsVerifier},
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, PoseidonRead, PoseidonWrite, TranscriptRead,
        },
    };
    use halo2_snark_aggregator_circuit::verify_circuit::{
        calc_verify_circuit_instances, verify_circuit_builder, Halo2VerifierCircuit,
    };

    use halo2_proofs::plonk::VerifyingKey;

    use pairing::group::ff::PrimeField;
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
    let poseidon_result = poseidon_result(&params);
    let zktrie_result = zktrie_result(&params);

    let profile_state = false;
    let profile_evm = false;
    let profile_both = true;

    if profile_state {
        run_verifier_circuit(
            "state_circuit",
            &params,
            vec![state_circuit_r.clone()],
            false,
        );
    }
    if profile_evm {
        run_verifier_circuit("evm_circuit", &params, vec![evm_circuit_r.clone()], false);
    }
    if profile_both {
        run_verifier_circuit(
            "both",
            &params,
            vec![evm_circuit_r, state_circuit_r, poseidon_result, zktrie_result],
            true,
        );
    }

    /*
    let stage2 = false;
    if stage2 {
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
