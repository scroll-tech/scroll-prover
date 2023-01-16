use ethers_providers::{Http, Provider};
use std::env;
use types::eth::BlockTrace;
use zkevm::circuit::SuperCircuit;
use zkevm::prover::Prover;

const DEFAULT_BEGIN_INDEX: i64 = 1;
const DEFAULT_END_INDEX: i64 = i64::MAX;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    log::info!("mock-testnet: begin");

    let setting = Setting::new();
    log::info!("mock-testnet: {setting:?}");

    let provider = Provider::<Http>::try_from(&setting.scroll_api_url)
        .expect("mock-testnet: failed to initialize ethers Provider");

    match setting.prove_type {
        ProveType::Batch => prove_by_batch(provider, setting).await,
        ProveType::Block => prove_by_block(provider, setting).await,
    }

    log::info!("move-testnet: end");
}

async fn prove_by_batch(provider: Provider<Http>, setting: Setting) {
    log::info!("move-testnet: prover-by-batch begin");

    for i in setting.begin_index..=setting.end_index {
        let block_traces: Vec<BlockTrace> = provider
            .request("l2_getTracesByBatchIndex", i)
            .await
            .expect("mock-testnet: failed to request l2_getTracesByBatchIndex with params [{i}]");

        match Prover::mock_prove_target_circuit_batch::<SuperCircuit>(&block_traces, true) {
            Ok(_) => log::info!("mock-testnet: succeeded to prove batch-{i}"),
            Err(err) => log::error!("mock-testnet: failed to prove batch-{i}:\n{err:?}"),
        }
    }

    log::info!("move-testnet: prover-by-batch end");
}

async fn prove_by_block(provider: Provider<Http>, setting: Setting) {
    log::info!("move-testnet: prover-by-block begin");

    for i in setting.begin_index..=setting.end_index {
        let block_trace: BlockTrace = provider
            .request("scroll_getBlockTraceByNumberOrHash", i)
            .await
            .expect("mock-testnet: failed to request scroll_getBlockTraceByNumberOrHash with params [{i}]");

        match Prover::mock_prove_target_circuit::<SuperCircuit>(&block_trace, true) {
            Ok(_) => log::info!("mock-testnet: succeeded to prove block-{i}"),
            Err(err) => log::error!("mock-testnet: failed to prove block-{i}:\n{err:?}"),
        }
    }

    log::info!("move-testnet: prover-by-block end");
}

#[derive(Debug)]
struct Setting {
    prove_type: ProveType,
    begin_index: i64,
    end_index: i64,
    scroll_api_url: String,
}

impl Setting {
    pub fn new() -> Self {
        let scroll_api_url =
            env::var("SCROLL_API_URL").expect("mock-testnet: Must set env SCROLL_API_URL");
        let prove_type = env::var("PROVE_TYPE").ok().unwrap_or_default().into();
        let begin_index = env::var("PROVE_BEGIN_INDEX")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(DEFAULT_BEGIN_INDEX);
        let end_index = env::var("PROVE_END_INDEX")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(DEFAULT_END_INDEX);

        Self {
            prove_type,
            begin_index,
            end_index,
            scroll_api_url,
        }
    }
}

#[derive(Debug)]
enum ProveType {
    Batch,
    Block,
}

impl From<String> for ProveType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "batch" => Self::Batch,
            _ => Self::Block,
        }
    }
}
