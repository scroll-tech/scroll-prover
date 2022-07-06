use clap::Parser;
use zkevm::{
    circuit::DEGREE,
    utils::{load_or_create_params, load_or_create_seed},
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// generate params and write into file
    #[clap(short, long = "params")]
    params_path: Option<String>,
    /// generate seed and write into file
    #[clap(short, long = "seed")]
    seed_path: Option<String>,
}

fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let args = Args::parse();
    if let Some(path) = args.params_path {
        load_or_create_params(&path, *DEGREE).expect("failed to load or create params");
    }
    if let Some(path) = args.seed_path {
        load_or_create_seed(&path).expect("failed to load or create seed");
    }
}
