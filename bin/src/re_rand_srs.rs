use anyhow::Result;
use clap::Parser;
use prover::utils::{load_params, re_randomize_srs};
use tiny_keccak::{Hasher, Keccak};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// degree of input param file
    #[clap(short, long = "param degree", default_value = "26")]
    degree: usize,
    /// input, old param file.
    #[clap(short, long = "input param", default_value = "old.param")]
    input_param: String,
    /// output, new param file.
    #[clap(short, long = "output param", default_value = "new.param")]
    output_param: String,
    /// Seed value for re-randomization.
    #[clap(short, long = "seed", default_value = "")]
    seed: String,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    log::info!("Re-randomize SRS in file: {}", args.input_param);
    log::info!("Degree of SRS: {}", args.degree);
    log::info!("Using seed: {}", args.seed);
    log::info!("Output new SRS to: {}", args.output_param);

    let mut old_param = load_params(&args.input_param, args.degree as u32, None)?;
    let mut hasher = Keccak::v256();
    hasher.update(args.seed.as_bytes());
    let mut seed = [0u8; 32];
    hasher.finalize(&mut seed);
    re_randomize_srs(&mut old_param, &seed);

    log::info!("SRS re-randomization finished");
    Ok(())
}
