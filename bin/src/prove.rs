use clap::Parser;
use std::fs::File;
use std::io::Write;
use zkevm::{
    circuit::{EvmCircuit, StateCircuit, AGG_DEGREE, DEGREE},
    prover::Prover,
    utils::{get_block_result_from_file, load_or_create_params, load_or_create_seed},
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Get params and write into file.
    #[clap(short, long = "params")]
    params_path: Option<String>,
    /// Get seed and write into file.
    #[clap(long = "seed")]
    seed_path: Option<String>,
    /// Get BlockTrace from file.
    #[clap(short, long = "trace")]
    trace_path: Option<String>,
    /// Generate evm proof and write into file.
    /// It will generate nothing if it is None.
    #[clap(long = "evm")]
    evm_proof_path: Option<String>,
    /// Generate state proof and write into file.
    /// It will generate nothing if it is None.
    #[clap(long = "state")]
    state_proof_path: Option<String>,
}

fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let args = Args::parse();
    let params = load_or_create_params(&args.params_path.clone().unwrap(), *DEGREE)
        .expect("failed to load or create params");
    let agg_params = load_or_create_params(&args.params_path.unwrap(), *AGG_DEGREE)
        .expect("failed to load or create params");
    let seed =
        load_or_create_seed(&args.seed_path.unwrap()).expect("failed to load or create seed");

    let mut prover = Prover::from_params_and_seed(params, agg_params, seed);
    let trace = get_block_result_from_file(&args.trace_path.unwrap());

    if let Some(path) = args.evm_proof_path {
        let evm_proof = prover
            .create_target_circuit_proof::<EvmCircuit>(&trace)
            .expect("cannot generate evm_proof");
        let mut f = File::create(path).unwrap();
        f.write_all(evm_proof.proof.as_slice()).unwrap();
    }

    if let Some(path) = args.state_proof_path {
        let state_proof = prover
            .create_target_circuit_proof::<StateCircuit>(&trace)
            .expect("cannot generate evm_proof");
        let mut f = File::create(path).unwrap();
        f.write_all(state_proof.proof.as_slice()).unwrap();
    }
}
