use git_version::git_version;
use glob::glob;
use once_cell::sync::Lazy;
use std::sync::Once;
use types::eth::BlockTrace;
use zkevm::utils::get_block_trace_from_file;
use zkevm::utils::read_env_var;

pub const GIT_VERSION: &str = git_version!();
pub const PARAMS_DIR: &str = "./test_params";
pub const SEED_PATH: &str = "./test_seed";

pub static ENV_LOGGER: Once = Once::new();

pub static PACK_DIR: Lazy<String> =
    Lazy::new(|| read_env_var("PACK_DIR", "tests/traces/bridge/".to_string()));

pub fn init() {
    dotenv::dotenv().ok();
    ENV_LOGGER.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    });
    log::info!("git version {}", GIT_VERSION);
}

pub fn load_packing_traces() -> (Vec<String>, Vec<types::eth::BlockTrace>) {
    let pack_dir = &*PACK_DIR;
    let file_names: Vec<String> = glob(&format!("{pack_dir}/**/*.json"))
        .unwrap()
        .map(|p| p.unwrap().to_str().unwrap().to_string())
        .collect();
    log::info!("test packing with {:?}", file_names);
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
