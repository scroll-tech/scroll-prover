use clap::Parser;
use rand_xorshift::XorShiftRng;
use rand::SeedableRng;
use std::fs::File;
use std::io::Write;
use zkevm::{
    circuit::DEGREE,
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
    #[clap(short, long = "rng")]
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
    let params = load_or_create_params(&args.params_path.unwrap(), *DEGREE)
        .expect("failed to load or create params");
    let seed = load_or_create_seed(&args.seed_path.unwrap()).expect("failed to load or create seed");
    let rng = XorShiftRng::from_seed(seed);

    let prover = Prover::from_params_and_rng(params, rng);
    let trace = get_block_result_from_file(&args.trace_path.unwrap());

    if let Some(path) = args.evm_proof_path {
        let evm_proof = prover
            .create_evm_proof(&trace)
            .expect("cannot generate evm_proof");
        let mut f = File::create(path).unwrap();
        f.write_all(evm_proof.as_slice()).unwrap();
    }

    if let Some(path) = args.state_proof_path {
        let state_proof = prover
            .create_state_proof(&trace)
            .expect("cannot generate evm_proof");
        let mut f = File::create(path).unwrap();
        f.write_all(state_proof.as_slice()).unwrap();
    }
}
