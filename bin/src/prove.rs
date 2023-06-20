use clap::Parser;
use log::info;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use zkevm::{
    circuit::AGG_DEGREE,
    prover::Prover,
    utils::{get_block_trace_from_file, init_env_and_log, load_or_create_params},
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Get params and write into file.
    #[clap(short, long = "params")]
    params_path: Option<String>,
    /// Get BlockTrace from file or dir.
    #[clap(short, long = "trace")]
    trace_path: Option<String>,
    /// Option means if generates agg circuit proof.
    /// Boolean means if output agg circuit proof.
    #[clap(long = "agg")]
    agg_proof: Option<bool>,
}

fn main() {
    init_env_and_log("prove");

    let args = Args::parse();
    let agg_params = load_or_create_params(&args.params_path.unwrap(), *AGG_DEGREE)
        .expect("failed to load or create params");

    let mut prover = Prover::from_params(agg_params);

    let mut traces = Vec::new();
    let trace_path = PathBuf::from(&args.trace_path.unwrap());
    if trace_path.is_dir() {
        for entry in fs::read_dir(trace_path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() && path.to_str().unwrap().ends_with(".json") {
                let block_trace = get_block_trace_from_file(path.to_str().unwrap());
                traces.push(block_trace);
            }
        }
    } else {
        let block_trace = get_block_trace_from_file(trace_path.to_str().unwrap());
        traces.push(block_trace);
    }

    if args.agg_proof.is_some() {
        let mut proof_path = PathBuf::from("agg.proof");

        let now = Instant::now();
        let agg_proof = prover
            .create_agg_circuit_proof_batch(traces.as_slice())
            .expect("cannot generate agg_proof");
        info!("finish generating agg proof, elapsed: {:?}", now.elapsed());

        if args.agg_proof.unwrap() {
            fs::create_dir_all(&proof_path).unwrap();
            agg_proof.dump(&mut proof_path).unwrap();
        }
    }
}
