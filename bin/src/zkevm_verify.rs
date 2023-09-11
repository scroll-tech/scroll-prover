use clap::Parser;
use prover::{utils::init_env_and_log, zkevm::Verifier, ChunkProof};
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
    // Layer config files are located in `./integration/configs`.
    env::set_current_dir("./integration").unwrap();
    init_env_and_log("bin_zkevm_verify");

    let args = Args::parse();
    let proof_path = PathBuf::from(&args.proof_path);

    env::set_var("CHUNK_VK_FILENAME", "vk_chunk_zkevm.vkey");
    let verifier = Verifier::from_dirs(&args.params_path, &proof_path.to_string_lossy());

    let proof =
        ChunkProof::from_json_file(&args.proof_path, "zkevm").expect("Proof file doesn't exist");

    let verified = verifier.verify_chunk_proof(proof);
    log::info!("verify chunk snark: {}", verified)
}
