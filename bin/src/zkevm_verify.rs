use clap::Parser;
use prover::{
    io::{load_snark, read_all},
    utils::init_env_and_log,
    zkevm::Verifier,
};
use std::{env, path::PathBuf};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Get params from the file.
    #[clap(short, long = "params", default_value = "test_params")]
    params_path: String,
    /// Get snark and vk from the folder.
    #[clap(long = "proof", default_value = "proof_data")]
    proof_path: String,
}

fn main() {
    // Layer config files are located in `./prover/configs`.
    env::set_current_dir("./prover").unwrap();
    init_env_and_log("bin_zkevm_verify");

    let args = Args::parse();
    let proof_path = PathBuf::from(args.proof_path);

    let vk = read_all(&proof_path.join("chunk_zkevm.vkey").to_string_lossy());
    let verifier = Verifier::from_params_dir(&args.params_path, &vk);

    let snark = load_snark(
        &proof_path
            .join("compression_snark_layer2_zkevm.json")
            .to_string_lossy(),
    )
    .unwrap()
    .expect("Snark file doesn't exist");

    let verified = verifier.verify_chunk_snark(snark);
    log::info!("verify chunk snark: {}", verified)
}
