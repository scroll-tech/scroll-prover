use clap::Parser;
use log::info;
use prover::utils::{init_env_and_log, load_or_create_params};
use prover::zkevm::circuit::{AGG_DEGREE, DEGREE};
use prover::zkevm::{AggCircuitProof, Verifier};
use std::fs::File;
use std::io::Read;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Get params from the file.
    #[clap(short, long = "params")]
    params_path: Option<String>,
    /// Get vk from the file.
    #[clap(long = "vk")]
    vk_path: Option<String>,
}

fn main() {
    init_env_and_log("verify");
    std::env::set_var("VERIFY_CONFIG", "./zkevm/configs/verify_circuit.config");

    let args = Args::parse();
    let params = load_or_create_params(&args.params_path.clone().unwrap(), *DEGREE)
        .expect("failed to load or create params");
    let agg_params = load_or_create_params(&args.params_path.unwrap(), *AGG_DEGREE)
        .expect("failed to load or create params");
    let agg_vk = read_from_file(&args.vk_path.unwrap());

    let v = Verifier::from_params(params, agg_params, Some(agg_vk));

    let proof_vec = read_from_file("agg.proof");
    let proof = serde_json::from_slice::<AggCircuitProof>(proof_vec.as_slice()).unwrap();
    let verified = v.verify_agg_circuit_proof(proof).is_ok();
    info!("verify agg proof: {}", verified)
}

fn read_from_file(path: &str) -> Vec<u8> {
    let mut f = File::open(path).unwrap();
    let mut buf = vec![];
    f.read_to_end(&mut buf).unwrap();
    buf
}
