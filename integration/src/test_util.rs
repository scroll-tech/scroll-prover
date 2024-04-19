use glob::glob;
use prover::{
    utils::{get_block_trace_from_file, read_env_var},
    BlockTrace,
};

mod capacity_checker;
pub mod mock_plonk;
mod proof;

pub use capacity_checker::{
    ccc_as_signer, ccc_by_chunk, prepare_circuit_capacity_checker, pretty_print_row_usage,
    run_circuit_capacity_checker,
};
pub use proof::{
    gen_and_verify_batch_proofs, gen_and_verify_chunk_proofs, gen_and_verify_normal_and_evm_proofs,
    gen_and_verify_normal_proof,
};

pub const ASSETS_DIR: &str = "./test_assets";
pub const PARAMS_DIR: &str = "./test_params";

pub fn load_block_traces_for_test() -> (Vec<String>, Vec<BlockTrace>) {
    let trace_path: String = read_env_var(
        "TRACE_PATH",
        "./tests/extra_traces/batch_495/chunk_495/block_8802.json".to_string(),
    );
    let paths: Vec<String> = if !std::fs::metadata(&trace_path).unwrap().is_dir() {
        vec![trace_path]
    } else {
        load_chunk_traces(&trace_path).0
    };
    log::info!("test cases traces: {:?}", paths);
    let traces: Vec<_> = paths.iter().map(get_block_trace_from_file).collect();
    (paths, traces)
}

fn load_chunk_traces(chunk_dir: &str) -> (Vec<String>, Vec<BlockTrace>) {
    // Nested dirs are not allowed
    let file_names: Vec<String> = glob(&format!("{chunk_dir}/*.json"))
        .unwrap()
        .map(|p| p.unwrap().to_str().unwrap().to_string())
        .collect();
    log::info!("test chunk with {:?}", file_names);
    let mut names_and_traces = file_names
        .into_iter()
        .map(|trace_path| {
            let trace: BlockTrace = get_block_trace_from_file(trace_path.clone());
            (
                trace_path,
                trace.clone(),
                trace.header.number.unwrap().as_u64(),
            )
        })
        .collect::<Vec<_>>();
    names_and_traces.sort_by(|a, b| a.2.cmp(&b.2));
    log::info!(
        "sorted: {:?}",
        names_and_traces
            .iter()
            .map(|(f, _, _)| f.clone())
            .collect::<Vec<String>>()
    );
    names_and_traces.into_iter().map(|(f, t, _)| (f, t)).unzip()
}

pub fn load_batch() -> anyhow::Result<Vec<String>> {
    let batch_dir = read_env_var("TRACE_PATH", "./tests/extra_traces/batch_24".to_string());
    let mut sorted_dirs: Vec<String> = std::fs::read_dir(batch_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<String>>();
    sorted_dirs.sort();
    log::info!("batch content: {:?}", sorted_dirs);
    Ok(sorted_dirs)
}
