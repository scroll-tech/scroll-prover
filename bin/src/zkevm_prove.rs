use clap::Parser;
use prover::{
    utils::{get_block_trace_from_file, init_env_and_log},
    zkevm::Prover,
};
use std::{env, fs, path::PathBuf, time::Instant};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Get params and write into file.
    #[clap(short, long = "params", default_value = "test_params")]
    params_path: String,
    /// Get BlockTrace from file or dir.
    #[clap(
        short,
        long = "trace",
        default_value = "tests/traces/erc20/10_transfer.json"
    )]
    trace_path: String,
}

fn main() {
    // Layer config files are located in `./prover/configs`.
    env::set_current_dir("./prover").unwrap();
    let output_dir = init_env_and_log("bin_zkevm_prove");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let args = Args::parse();
    let mut prover = Prover::from_params_dir(&args.params_path);

    let mut traces = Vec::new();
    let trace_path = PathBuf::from(&args.trace_path);
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

    let now = Instant::now();
    prover
        .gen_chunk_proof(traces, Some("zkevm"), Some(&output_dir))
        .expect("cannot generate chunk snark");
    log::info!(
        "finish generating chunk snark, elapsed: {:?}",
        now.elapsed()
    );
}
