use anyhow::Result;
use ethers_providers::{Http, Provider};
use itertools::Itertools;
use prover::{
    inner::Prover,
    utils::init_env_and_log,
    zkevm::circuit::{
        block_traces_to_witness_block, calculate_row_usage_of_witness_block, SuperCircuit,
        SUB_CIRCUIT_NAMES,
    },
};
use reqwest::Url;
use serde::Deserialize;
use std::env;
use types::eth::BlockTrace;

const DEFAULT_BEGIN_BATCH: i64 = 1;
const DEFAULT_END_BATCH: i64 = i64::MAX;

#[tokio::main]
async fn main() {
    init_env_and_log("mock_testnet");

    log::info!("mock-testnet: begin");

    let setting = Setting::new();
    log::info!("mock-testnet: {setting:?}");

    let provider = Provider::<Http>::try_from(&setting.l2geth_api_url)
        .expect("mock-testnet: failed to initialize ethers Provider");

    for i in setting.begin_batch..=setting.end_batch {
        log::info!("mock-testnet: requesting block traces of batch {i}");

        let block_traces = match setting.prove_type {
            ProveType::Batch => get_traces_by_batch_api(&provider, &setting, i).await,
            ProveType::Block => get_traces_by_block_api(&provider, &setting, i).await,
        };

        let block_traces = block_traces
            .unwrap_or_else(|_| panic!("mock-testnet: failed to request API with batch-{i}"));

        if let Some(block_traces) = block_traces {
            let rows_only = true;
            let result = (|| {
                if rows_only {
                    let gas_total: u64 = block_traces
                        .iter()
                        .map(|b| b.header.gas_used.as_u64())
                        .sum();
                    let witness_block = block_traces_to_witness_block(&block_traces)?;
                    let rows = calculate_row_usage_of_witness_block(&witness_block)?;
                    log::info!(
                        "rows of batch {}(block range {:?} to {:?}):",
                        i,
                        block_traces.first().and_then(|b| b.header.number),
                        block_traces.last().and_then(|b| b.header.number),
                    );
                    for (c, r) in SUB_CIRCUIT_NAMES.iter().zip_eq(rows.iter()) {
                        log::info!("rows of {}: {}", c, r);
                    }
                    let row_num = rows.iter().max().unwrap();
                    log::info!(
                        "final rows of batch {}: row {}, gas {}, gas/row {:.2}",
                        i,
                        row_num,
                        gas_total,
                        gas_total as f64 / *row_num as f64
                    );
                    Ok(())
                } else {
                    Prover::<SuperCircuit>::mock_prove_target_circuit_batch(&block_traces)
                }
            })();
            match result {
                Ok(_) => log::info!("mock-testnet: succeeded to prove batch-{i}"),
                Err(err) => log::error!("mock-testnet: failed to prove batch-{i}:\n{err:?}"),
            }
        } else {
            log::info!("mock-testnet: finished to prove at batch-{i}");
            break;
        }
    }

    log::info!("mock-testnet: end");
}

/// Request block traces by API `l2_getTracesByBatchIndex`. Return None for no more batches.
async fn get_traces_by_batch_api(
    provider: &Provider<Http>,
    _setting: &Setting,
    batch_index: i64,
) -> Result<Option<Vec<BlockTrace>>> {
    // TODO: need to test this API.
    Ok(Some(
        provider
            .request("l2_getTracesByBatchIndex", [format!("{batch_index:#x}")])
            .await?,
    ))
}

/// Request block traces by API `scroll_getBlockTraceByNumberOrHash`. Return None for no more
/// batches.
async fn get_traces_by_block_api(
    provider: &Provider<Http>,
    setting: &Setting,
    batch_index: i64,
) -> Result<Option<Vec<BlockTrace>>> {
    let url = Url::parse_with_params(
        &setting.rollupscan_api_url,
        &[("index", batch_index.to_string())],
    )?;

    let resp: RollupscanResponse = reqwest::get(url).await?.json().await?;

    Ok(if let Some(batch) = resp.batch {
        let mut traces = vec![];
        for i in batch.start_block_number..=batch.end_block_number {
            log::info!("mock-testnet: requesting trace of block {i}");

            let trace = provider
                .request("scroll_getBlockTraceByNumberOrHash", [format!("{i:#x}")])
                .await?;
            traces.push(trace);
        }

        Some(traces)
    } else {
        None
    })
}

#[derive(Deserialize)]
struct RollupscanResponse {
    batch: Option<RollupscanBatch>,
}

#[derive(Deserialize)]
struct RollupscanBatch {
    start_block_number: i64,
    end_block_number: i64,
}

#[derive(Debug)]
struct Setting {
    prove_type: ProveType,
    begin_batch: i64,
    end_batch: i64,
    l2geth_api_url: String,
    rollupscan_api_url: String,
}

impl Setting {
    pub fn new() -> Self {
        let l2geth_api_url =
            env::var("L2GETH_API_URL").expect("mock-testnet: Must set env L2GETH_API_URL");
        let prove_type = env::var("PROVE_TYPE").ok().unwrap_or_default().into();
        let rollupscan_api_url = env::var("ROLLUPSCAN_API_URL");
        let rollupscan_api_url = match prove_type {
            ProveType::Batch => rollupscan_api_url.unwrap_or_default(),
            ProveType::Block => rollupscan_api_url
                .expect("mock-testnet: Must set env ROLLUPSCAN_API_URL for block type"),
        };
        let begin_batch = env::var("PROVE_BEGIN_BATCH")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(DEFAULT_BEGIN_BATCH);
        let end_batch = env::var("PROVE_END_BATCH")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(DEFAULT_END_BATCH);

        Self {
            prove_type,
            begin_batch,
            end_batch,
            l2geth_api_url,
            rollupscan_api_url,
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
