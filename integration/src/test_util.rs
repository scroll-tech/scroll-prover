use std::path::{Path, PathBuf};

use glob::glob;
use prover::{
    utils::{get_block_trace_from_file, read_env_var},
    BlockTrace,
};

pub const ASSETS_DIR: &str = "./test_assets";
pub const PARAMS_DIR: &str = "./params";

pub fn trace_path_for_test() -> String {
    read_env_var(
        "TRACE_PATH",
        "tests/extra_traces/batch_34700/chunk_1236462/block_4176564.json".to_string(),
    )
}

pub fn load_chunk_for_test() -> (Vec<String>, Vec<BlockTrace>) {
    load_chunk(&trace_path_for_test())
}

pub fn load_chunk(trace_path: &str) -> (Vec<String>, Vec<BlockTrace>) {
    let paths: Vec<String> = if !std::fs::metadata(trace_path).unwrap().is_dir() {
        vec![trace_path.to_string()]
    } else {
        // Nested dirs are not allowed
        let mut file_names: Vec<String> = glob(&format!("{trace_path}/*.json"))
            .unwrap()
            .map(|p| p.unwrap().to_str().unwrap().to_string())
            .collect();
        file_names.sort_by_key(|s| {
            let path = Path::new(s);
            let basename = path.file_stem().unwrap().to_str().unwrap();
            basename
                .trim_start_matches("block_")
                .parse::<u32>()
                .unwrap()
        });
        file_names
    };
    log::info!("test cases traces: {:?}", paths);
    let traces: Vec<_> = paths.iter().map(get_block_trace_from_file).collect();
    (paths, traces)
}

pub fn load_batch(batch_dir: &str) -> anyhow::Result<Vec<String>> {
    let sorted_dirs = read_dir_recursive(batch_dir, "chunk_")?;
    log::info!("batch content: {:?}", sorted_dirs);
    Ok(sorted_dirs)
}

/// Reads inside a directory recursively and returns paths to all sub-directories that match the
/// given prefix.
pub fn read_dir_recursive(dir: impl AsRef<Path>, prefix: &str) -> anyhow::Result<Vec<String>> {
    let mut sorted_dirs: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<String>>();
    sorted_dirs.sort_by_key(|s| {
        let path = Path::new(s);
        let dir_name = path.file_name().unwrap().to_string_lossy();
        dir_name.trim_start_matches(prefix).parse::<u32>().unwrap()
    });
    Ok(sorted_dirs)
}

/// Reads inside a directory and returns all files.
pub fn read_dir(dir: impl AsRef<Path>) -> anyhow::Result<Vec<PathBuf>> {
    let mut sorted_files = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    sorted_files.sort();
    Ok(sorted_files)
}
