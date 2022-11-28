use std::sync::Once;

use git_version::git_version;

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

pub fn parse_trace_path_from_mode(mode: &str) -> &'static str {
    let trace_path = match mode {
        "empty" => "./tests/traces/empty.json",
        "greeter" => "./tests/traces/greeter.json",
        "single" => "./tests/traces/erc20/single.json",
        "multiple" => "./tests/traces/erc20/multiple.json",
        "native" => "./tests/traces/native-transfer.json",
        "dao" => "./tests/traces/dao/propose.json",
        "nft" => "./tests/traces/nft/mint.json",
        "sushi" => "./tests/traces/sushi/chef-withdraw.json",
        _ => "./tests/traces/erc20/multiple.json",
    };
    log::info!("using mode {:?}, testing with {:?}", mode, trace_path);
    trace_path
}
