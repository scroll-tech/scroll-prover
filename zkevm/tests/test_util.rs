use chrono::Utc;
use git_version::git_version;
use glob::glob;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Once;
use types::eth::BlockTrace;
use zkevm::utils::get_block_trace_from_file;
use zkevm::utils::read_env_var;

pub const GIT_VERSION: &str = git_version!();
pub const PARAMS_DIR: &str = "./test_params";
pub const SEED_PATH: &str = "./test_seed";

pub static ENV_LOGGER: Once = Once::new();

pub fn init() {
    ENV_LOGGER.call_once(|| {
        dotenv::dotenv().ok();
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
        log::info!("git version {}", GIT_VERSION);
    });
}

pub fn create_output_dir() -> String {
    let mode = read_env_var("MODE", "multi".to_string());
    let output = read_env_var(
        "OUTPUT_DIR",
        format!("output_{}_{}", Utc::now().format("%Y%m%d_%H%M%S"), mode),
    );

    let output_dir = PathBuf::from_str(&output).unwrap();
    fs::create_dir_all(output_dir).unwrap();

    output
}

pub fn load_batch_traces(batch_dir: &str) -> (Vec<String>, Vec<types::eth::BlockTrace>) {
    let file_names: Vec<String> = glob(&format!("{batch_dir}/**/*.json"))
        .unwrap()
        .map(|p| p.unwrap().to_str().unwrap().to_string())
        .collect();
    log::info!("test batch with {:?}", file_names);
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

pub fn parse_trace_path_from_mode(mode: &str) -> &'static str {
    let trace_path = match mode {
        "empty" => "./tests/traces/empty.json",
        "greeter" => "./tests/traces/greeter.json",
        "single" => "./tests/traces/erc20/single.json",
        "multiple" => "./tests/traces/erc20/multiple.json",
        "native" => "./tests/traces/native_transfer.json",
        "dao" => "./tests/traces/dao/propose.json",
        "nft" => "./tests/traces/nft/mint.json",
        "sushi" => "./tests/traces/sushi/chef_withdraw.json",
        _ => "./tests/traces/erc20/multiple.json",
    };
    log::info!("using mode {:?}, testing with {:?}", mode, trace_path);
    trace_path
}

pub fn load_block_traces_for_test() -> (Vec<String>, Vec<BlockTrace>) {
    let trace_path: String = read_env_var("TRACE_PATH", "".to_string());
    let paths: Vec<String> = if trace_path.is_empty() {
        // use mode
        let mode = read_env_var("MODE", "multiple".to_string());
        if mode.to_lowercase() == "batch" || mode.to_lowercase() == "pack" {
            (1..=10)
                .map(|i| format!("tests/traces/bridge/{:02}.json", i))
                .collect()
        } else {
            vec![parse_trace_path_from_mode(&mode).to_string()]
        }
    } else if !std::fs::metadata(&trace_path).unwrap().is_dir() {
        vec![trace_path]
    } else {
        load_batch_traces(&trace_path).0
    };
    log::info!("test cases traces: {:?}", paths);
    let traces: Vec<_> = paths.iter().map(get_block_trace_from_file).collect();
    (paths, traces)
}
