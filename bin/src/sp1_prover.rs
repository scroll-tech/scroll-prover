use clap::Parser;
use integration::test_util::load_chunk;
use prover::{init_env_and_log, gen_rng, ChunkProvingTask};
use scroll_prover::Sp1Prover;
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
    let output_dir = init_env_and_log("sp1_prover");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let args = Args::parse();

    let traces = load_chunk(&args.trace_path).1;
    prover::eth_types::constants::set_scroll_block_constants_with_trace(&traces[0]);
    let chunk = ChunkProvingTask::new(traces);
    let params_map = prover::Prover::load_params_map(
        &args.params_path,
        &[
            *prover::INNER_DEGREE,
            *prover::LAYER1_DEGREE,
            *prover::LAYER2_DEGREE,
        ],
    );

    let mut prover = Sp1Prover::from_params_and_assets(&params_map, &args.assets_path);
    log::info!("Constructed sp1 prover");

    let mut rng = gen_rng();
    let now = std::time::Instant::now();
    let _chunk_snark = prover
        .gen_sp1_snark(&mut rng, chunk.block_traces)
        .expect("cannot generate sp1 snark");
    log::info!(
        "finish generating sp1 snark, elapsed: {:?}",
        now.elapsed()
    );

    // prove_and_verify_chunk(
    //     chunk,
    //     Some("0"), // same with `make test-chunk-prove`, to load vk
    //     &params_map,
    //     &args.assets_path,
    //     &output_dir,
    // );
    log::info!("sp1 prove done");
}
