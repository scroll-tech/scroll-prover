use clap::Parser;
use prover::{io::read_all, utils::init_env_and_log, zkevm::Verifier, ChunkProof};
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

    let vk = read_all(&proof_path.join("chunk_vk_zkevm.vkey").to_string_lossy());
    let verifier = Verifier::from_params_dir(&args.params_path, &vk);

    let proof =
        ChunkProof::from_file("zkevm", &args.params_path).expect("Proof file doesn't exist");

    let verified = verifier.verify_chunk_proof(proof);
    log::info!("verify chunk snark: {}", verified)
}
