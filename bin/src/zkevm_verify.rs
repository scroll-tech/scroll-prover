use clap::Parser;
use prover::{io::read_all, utils::init_env_and_log, zkevm::Verifier, Proof};
use std::{env, path::PathBuf};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Get params from the file.
    #[clap(short, long = "params", default_value = "test_params")]
    params_path: String,
    /// Get vk and proof from the folder.
    #[clap(long = "proof", default_value = "proof_data")]
    proof_path: String,
}

fn main() {
    // Layer config files are located in `./prover/configs`.
    env::set_current_dir("./prover").unwrap();
    init_env_and_log("bin_zkevm_verify");

    let args = Args::parse();
    let proof_path = PathBuf::from(args.proof_path);

    let vk = read_all(&proof_path.join("chunk.vkey").to_string_lossy());
    let verifier = Verifier::from_params_dir(&args.params_path, &vk);

    let proof = read_all(&proof_path.join("chunk_full_proof.json").to_string_lossy());
    let proof = serde_json::from_slice::<Proof>(&proof).unwrap();

    let verified = verifier.verify_chunk_proof(proof);
    log::info!("verify chunk proof: {}", verified)
}
