use clap::Parser;
use prover::{
    utils::{get_block_trace_from_file, init_env_and_log},
    zkevm::Prover,
    ChunkProvingTask,
};
use std::{env, path::PathBuf};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Get params dir path.
    #[clap(short, long = "params", default_value = "test_params")]
    params_path: String,
    /// Get asserts dir path.
    #[clap(short, long = "assets", default_value = "test_assets")]
    assets_path: String,
    /// Get BlockTrace from file or dir.
    #[clap(
        short,
        long = "trace",
        default_value = "tests/traces/erc20/10_transfer.json"
    )]
    trace_path: String,
}

fn main() {
    // Layer config files are located in `./integration/configs`.
    env::set_current_dir("./integration").unwrap();
    let output_dir = init_env_and_log("bin_zkevm_prove");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let args = Args::parse();
    let mut prover = Prover::from_dirs(&args.params_path, &args.assets_path);

    let trace_path = PathBuf::from(&args.trace_path);

    let trace_paths = if trace_path.is_dir() {
        glob::glob(&format!("{}/**/*.json", args.trace_path))
            .unwrap()
            .collect::<Result<Vec<PathBuf>, _>>()
            .unwrap()
    } else {
        vec![trace_path]
    };

    for path in trace_paths.into_iter() {
        let block_trace = get_block_trace_from_file(path.to_str().unwrap());
        env::set_var("CHAIN_ID", block_trace.chain_id.to_string());
        log::info!("PROVE START {path:?}");
        match prover
            .gen_chunk_proof(
                ChunkProvingTask::from(vec![block_trace]),
                Some("zkevm"),
                None,
                Some(&output_dir),
            ) {
            Ok(_) => log::info!("PROVE SUCCESS {path:?}"),
            Err(e) => log::error!("PROVE ERROR {path:?}, err: {e:?}"),
        }
    }
}
