use std::sync::Once;

use git_version::git_version;
use zkevm::utils::get_block_trace_from_file;

pub const GIT_VERSION: &str = git_version!();
pub const PARAMS_DIR: &str = "./test_params";
pub const SEED_PATH: &str = "./test_seed";

pub static ENV_LOGGER: Once = Once::new();

pub fn init() {
    dotenv::dotenv().ok();
    ENV_LOGGER.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    });
    log::info!("git version {}", GIT_VERSION);
}

pub fn load_packing_traces() -> Vec<types::eth::BlockTrace> {
    let mut block_traces = Vec::new();
    for block_number in 1..=10 {
        let trace_path = format!("tests/traces/bridge/{:02}.json", block_number);
        let block_trace = get_block_trace_from_file(trace_path);
        block_traces.push(block_trace);
    }
    block_traces
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
