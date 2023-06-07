use clap::Parser;
use log::info;
use std::fs::File;
use std::io::Read;
use zkevm::prover::{AggCircuitProof, TargetCircuitProof};
use zkevm::verifier::Verifier;
use zkevm::{
    circuit::{SuperCircuit, AGG_DEGREE, DEGREE},
    utils::{init_env_and_log, load_or_create_params},
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Get params from the file.
    #[clap(short, long = "params")]
    params_path: Option<String>,
    /// Get vk from the file.
    #[clap(long = "vk")]
    vk_path: Option<String>,
    /// the path of super circuit proof to verify.
    #[clap(long = "super")]
    super_proof: Option<String>,
    /// the path of agg circuit proof to verify.
    #[clap(long = "agg")]
    agg_proof: Option<String>,
}

fn main() {
    init_env_and_log("verify");

    let args = Args::parse();
    let params = load_or_create_params(&args.params_path.clone().unwrap(), *DEGREE)
        .expect("failed to load or create params");
    let agg_params = load_or_create_params(&args.params_path.unwrap(), *AGG_DEGREE)
        .expect("failed to load or create params");
    let agg_vk = read_from_file(&args.vk_path.unwrap());

    let mut v = Verifier::from_params(params, agg_params, Some(agg_vk));
    if let Some(path) = args.super_proof {
        let proof_vec = read_from_file(&path);
        let proof = serde_json::from_slice::<TargetCircuitProof>(proof_vec.as_slice()).unwrap();
        let verified = v
            .verify_target_circuit_proof::<SuperCircuit>(&proof)
            .is_ok();
        info!("verify super proof: {}", verified)
    }
    if let Some(path) = args.agg_proof {
        let proof_vec = read_from_file(&path);
        let proof = serde_json::from_slice::<AggCircuitProof>(proof_vec.as_slice()).unwrap();
        let verified = v.verify_agg_circuit_proof(proof).is_ok();
        info!("verify agg proof: {}", verified)
    }
}

fn read_from_file(path: &str) -> Vec<u8> {
    let mut f = File::open(path).unwrap();
    let mut buf = vec![];
    f.read_to_end(&mut buf).unwrap();
    buf
}
