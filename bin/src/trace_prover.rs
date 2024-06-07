use clap::Parser;
use integration::test_util::prove_and_verify_chunk;
use prover::utils::init_env_and_log;
use std::env;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Get params dir path.
    #[clap(short, long = "params", default_value = "params")]
    params_path: String,
    /// Get asserts dir path.
    #[clap(short, long = "assets", default_value = "test_assets")]
    assets_path: String,
    /// Get BlockTrace from file or dir.
    #[clap(
        short,
        long = "trace",
        default_value = "tests/extra_traces/batch_34700/chunk_1236462/block_4176564.json"
    )]
    trace_path: String,
}

fn main() {
    // Layer config files are located in `./integration/configs`.
    env::set_current_dir("./integration").unwrap();
    let output_dir = init_env_and_log("trace_prover");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let args = Args::parse();
    prove_and_verify_chunk(
        &args.trace_path,
        Some("test"),
        &args.params_path,
        &args.assets_path,
        &output_dir,
    );
}
