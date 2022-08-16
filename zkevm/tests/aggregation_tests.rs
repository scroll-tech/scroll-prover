use halo2_proofs::pairing::bn256::{Bn256, G1Affine};
use halo2_snark_aggregator_circuit::verify_circuit::ProvedCircuit;
use halo2_snark_aggregator_solidity::SolidityGenerate;
use std::fs::{self};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Once;
use types::eth::BlockResult;
use zkevm::prover::AggCircuitProof;
use zkevm::verifier::Verifier;
use zkevm::{io::*, prover::Prover};

const PARAMS_PATH: &str = "./test_params";
const SEED_PATH: &str = "./test_seed";
static ENV_LOGGER: Once = Once::new();

fn parse_trace_path_from_env(mode: &str) -> &'static str {
    let trace_path = match mode {
        "empty" => "./tests/traces/empty.json",
        "greeter" => "./tests/traces/greeter.json",
        "multiple" => "./tests/traces/multiple-erc20.json",
        "native" => "./tests/traces/native-transfer.json",
        "single" => "./tests/traces/single-erc20.json",
        "dao" => "./tests/traces/dao.json",
        "nft" => "./tests/traces/nft.json",
        "sushi" => "./tests/traces/masterchef.json",
        _ => "./tests/traces/multiple-erc20.json",
    };
    log::info!("using mode {:?}, testing with {:?}", mode, trace_path);
    trace_path
}

fn init() {
    dotenv::dotenv().ok();
    ENV_LOGGER.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    });
    log::trace!("TRACE LOG example");
    log::debug!("DEBUG LOG example");
    log::info!("INFO LOG example");
    log::warn!("WARN LOG example");
    log::error!("ERROR LOG example");
    println!("STDOUT example");
    eprintln!("STDERR example");
}

fn _write_vk(output_dir: &str, c: &ProvedCircuit<G1Affine, Bn256>) {
    let mut fd = std::fs::File::create(&format!("{}/vk_{}", output_dir, c.name)).unwrap();
    c.vk.write(&mut fd).unwrap();
}

fn verifier_circuit_prove(output_dir: &str, block_result: &BlockResult) {
    log::info!("output files to {}", output_dir);
    fs::create_dir_all(output_dir).unwrap();
    let mut out_dir = PathBuf::from_str(output_dir).unwrap();

    let mut prover = Prover::from_fpath(PARAMS_PATH, SEED_PATH);
    //prover.init_agg_pk().unwrap();
    let agg_proof = prover.create_agg_circuit_proof(block_result).unwrap();
    agg_proof.write_to_dir(&mut out_dir);
}

fn verifier_circuit_generate_solidity(dir: &str) {
    let template_folder =
        PathBuf::from("../../halo2-snark-aggregator/halo2-snark-aggregator-solidity/templates");
    let mut folder = PathBuf::from_str(dir).unwrap();

    let params = read_all(&format!("{}/params26", PARAMS_PATH));

    let request = SolidityGenerate {
        params,
        vk: load_verify_circuit_vk(&mut folder),
        instance: load_verify_circuit_instance(&mut folder),
        proof: load_verify_circuit_proof(&mut folder),
    };
    let sol = request.call::<G1Affine, Bn256>(template_folder);
    write_verify_circuit_solidity(&mut folder, &Vec::<u8>::from(sol.as_bytes()));
    log::info!("write to {}/verifier.sol", dir);
}

fn verifier_circuit_verify(d: &str) {
    let mut folder = PathBuf::from_str(d).unwrap();
    let vk = load_verify_circuit_vk(&mut folder);
    let verifier = Verifier::from_fpath(PARAMS_PATH, Some(vk.clone()));

    let proof = load_verify_circuit_proof(&mut folder);
    let instance = load_verify_circuit_instance(&mut folder);

    let agg_proof = AggCircuitProof {
        proof_rust: proof,
        proof_solidity: vec![], // not used
        instance,
        instance_commitments: vec![], // not used
        vk,
    };
    assert!(verifier.verify_agg_circuit_proof(agg_proof).is_ok())
}

//#[cfg(feature = "prove_verify")]
#[test]
fn test_5in1() {
    use chrono::Utc;
    use zkevm::utils::{get_block_result_from_file, read_env_var};

    init();
    let exp_name = read_env_var("EXP", "".to_string());
    let mode = read_env_var("MODE", "greeter".to_string());
    let output = if exp_name.is_empty() {
        format!("output_{}_{}", Utc::now().format("%Y%m%d_%H%M%S"), mode)
    } else {
        exp_name
    };
    log::info!("output dir {}", output);
    {
        let output_dir = PathBuf::from_str(&output).unwrap();
        fs::create_dir_all(output_dir).unwrap();
    }
    log::info!("loading setup params");
    let trace_path = parse_trace_path_from_env(&mode);
    let block_result = get_block_result_from_file(trace_path);

    verifier_circuit_prove(&output, &block_result);
    verifier_circuit_verify(&output);
    let gen_soli: bool = read_env_var("GEN_SOLI", false);
    if gen_soli {
        verifier_circuit_generate_solidity(&output);
    }
}
