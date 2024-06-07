use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use glob::glob;
use log::info;
use prover::{
    utils::{get_block_trace_from_file, read_env_var},
    BlockTrace,
};

mod capacity_checker;
mod prove;

pub use capacity_checker::{
    ccc_as_signer, ccc_by_chunk, prepare_circuit_capacity_checker, pretty_print_row_usage,
    run_circuit_capacity_checker,
};
pub use prove::{new_batch_prover, prove_and_verify_batch};

pub const ASSETS_DIR: &str = "./test_assets";
pub const PARAMS_DIR: &str = "./params";

pub fn load_chunk_for_test() -> (Vec<String>, Vec<BlockTrace>) {
    let trace_path = read_env_var(
        "TRACE_PATH",
        "./tests/extra_traces/batch_495/chunk_495/block_8802.json".to_string(),
    );
    load_chunk(&trace_path).unwrap()
}

pub fn load_chunk(trace_path: &str) -> Result<(Vec<String>, Vec<BlockTrace>)> {
    let paths = collect_paths(trace_path)?;
    info!("test cases traces: {:?}", paths);
    let traces: Vec<_> = paths.iter().map(|path| get_block_trace_from_file(path)).collect();
    Ok((paths, traces))
}

fn collect_paths(trace_path: &str) -> Result<Vec<String>> {
    let path = Path::new(trace_path);
    if !path.is_dir() {
        return Ok(vec![trace_path.to_string()]);
    }

    let mut file_names: Vec<String> = glob(&format!("{}/*.json", trace_path))
        .context("Failed to read glob pattern")?
        .filter_map(Result::ok)
        .map(|p| p.to_str().unwrap().to_string())
        .collect();

    file_names.sort_by_key(|s| {
        Path::new(s)
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .trim_start_matches("block_")
            .parse::<u32>()
            .unwrap()
    });

    Ok(file_names)
}

pub fn load_batch(batch_dir: &str) -> Result<Vec<String>> {
    let mut sorted_dirs: Vec<String> = fs::read_dir(batch_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .map(|path| path.to_string_lossy().into_owned())
        .collect();

    sorted_dirs.sort_by_key(|s| {
        Path::new(s)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .trim_start_matches("chunk_")
            .parse::<u32>()
            .unwrap()
    });

    let fast = false;  // Consider making this a parameter if configurable
    if fast {
        sorted_dirs.truncate(1);
    }

    info!("batch content: {:?}", sorted_dirs);
    Ok(sorted_dirs)
}
