use integration::test_util::{load_block_traces_for_test, ASSETS_DIR, PARAMS_DIR};
use prover::{utils::init_env_and_log, zkevm::Prover};
use std::process::{Command, Stdio};

#[cfg(feature = "prove_verify")]
#[test]
fn test_chunk_prove_verify() {
    let output_dir = init_env_and_log("chunk_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let mut prover = Prover::from_dirs(PARAMS_DIR, ASSETS_DIR);
    log::info!("Constructed chunk prover");

    let chunk_trace = load_block_traces_for_test().1;
    log::info!("Loaded chunk trace");

    for i in 0..50 {
        log::info!("Proof-{i} BEGIN mem: {}", mem_usage());
        prover
            .gen_chunk_proof(chunk_trace.clone(), None, None, None)
            .unwrap();
        log::info!("Proof-{i} END mem: {}", mem_usage());
    }
}

fn mem_usage() -> String {
    let cmd = Command::new("echo")
        .stdout(Stdio::piped())
        .arg("$(date '+%Y-%m-%d %H:%M:%S') $(free -g | grep Mem: | sed 's/Mem://g')")
        .spawn()
        .unwrap();
    let output = cmd.wait_with_output().unwrap().stdout;
    String::from_utf8_lossy(&output).to_string()
}
