use glob::glob;
use prover::{
    utils::{get_block_trace_from_file, read_env_var},
    BlockTrace,
};

mod capacity_checker;
mod proof;
mod types;

pub use prover::types::BatchProvingTask;

pub use capacity_checker::{
    ccc_as_signer, ccc_by_chunk, prepare_circuit_capacity_checker, pretty_print_row_usage,
    run_circuit_capacity_checker,
};
pub use proof::{
    gen_and_verify_batch_proofs, gen_and_verify_chunk_proofs, gen_and_verify_normal_and_evm_proofs,
    gen_and_verify_normal_proof,
};

pub const ASSETS_DIR: &str = "./test_assets";
pub const PARAMS_DIR: &str = "./params";

pub fn load_chunk_for_test() -> (Vec<String>, Vec<BlockTrace>) {
    let trace_path: String = read_env_var(
        "TRACE_PATH",
        "./tests/extra_traces/batch_495/chunk_495/block_8802.json".to_string(),
    );
    load_chunk(&trace_path)
}

pub fn load_chunk(trace_path: &str) -> (Vec<String>, Vec<BlockTrace>) {
    let paths: Vec<String> = if !std::fs::metadata(&trace_path).unwrap().is_dir() {
        vec![trace_path.to_string()]
    } else {
        // Nested dirs are not allowed
        let mut file_names: Vec<String> = glob(&format!("{trace_path}/*.json"))
            .unwrap()
            .map(|p| p.unwrap().to_str().unwrap().to_string())
            .collect();
        file_names.sort_by_key(|s| {
            // Remove the ".json" suffix and parse the remaining part as an integer
            s.trim_end_matches(".json").parse::<u32>().unwrap()
        });
        file_names
    };
    log::info!("test cases traces: {:?}", paths);
    let traces: Vec<_> = paths.iter().map(get_block_trace_from_file).collect();
    (paths, traces)
}
