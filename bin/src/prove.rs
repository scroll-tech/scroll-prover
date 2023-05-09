use clap::Parser;
use log::info;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use zkevm::{
    circuit::{SuperCircuit, AGG_DEGREE},
    prover::Prover,
    utils::{get_block_trace_from_file, load_or_create_params},
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
    /// Option means if generates super circuit proof.
    /// Boolean means if output super circuit proof.
    #[clap(long = "super")]
    super_proof: Option<bool>,
    /// Option means if generates agg circuit proof.
    /// Boolean means if output agg circuit proof.
    #[clap(long = "agg")]
    agg_proof: Option<bool>,
}

fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let args = Args::parse();
    let agg_params = load_or_create_params(&args.params_path.unwrap(), *AGG_DEGREE)
        .expect("failed to load or create params");

    let mut prover = Prover::from_params(agg_params);

    let mut traces = HashMap::new();
    let trace_path = PathBuf::from(&args.trace_path.unwrap());
    if trace_path.is_dir() {
        for entry in fs::read_dir(trace_path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() && path.to_str().unwrap().ends_with(".json") {
                let block_trace = get_block_trace_from_file(path.to_str().unwrap());
                traces.insert(path.file_stem().unwrap().to_os_string(), block_trace);
            }
        }
    } else {
        let block_trace = get_block_trace_from_file(trace_path.to_str().unwrap());
        traces.insert(trace_path.file_stem().unwrap().to_os_string(), block_trace);
    }

    let outer_now = Instant::now();
    for (trace_name, trace) in traces {
        if args.super_proof.is_some() {
            let proof_path = PathBuf::from(&trace_name).join("super.proof");

            let now = Instant::now();
            let super_proof = prover
                .create_target_circuit_proof::<SuperCircuit>(&trace)
                .expect("cannot generate evm_proof");
            info!(
                "finish generating evm proof of {}, elapsed: {:?}",
                &trace.header.hash.unwrap(),
                now.elapsed()
            );

            if args.super_proof.unwrap() {
                let mut f = File::create(&proof_path).unwrap();
                f.write_all(super_proof.snark.proof.as_slice()).unwrap();
            }
        }

        if args.agg_proof.is_some() {
            let mut proof_path = PathBuf::from(&trace_name).join("agg.proof");

            let now = Instant::now();
            let agg_proof = prover
                .create_agg_circuit_proof(&trace)
                .expect("cannot generate agg_proof");
            info!(
                "finish generating agg proof of {}, elapsed: {:?}",
                &trace.header.hash.unwrap(),
                now.elapsed()
            );

            if args.agg_proof.unwrap() {
                fs::create_dir_all(&proof_path).unwrap();
                agg_proof.dump(&mut proof_path).unwrap();
            }
        }
    }
    info!("finish generating all, elapsed: {:?}", outer_now.elapsed());
}
