#![allow(dead_code)]
use anyhow::Result;
use ethers_providers::{Http, Provider};
use prover::{
    inner::Prover,
    types::eth::BlockTrace,
    utils::init_env_and_log,
    zkevm::circuit::{
        block_traces_to_witness_block, calculate_row_usage_of_witness_block, SuperCircuit,
        WitnessBlock,
    },
};
use reqwest::Url;
use serde::Deserialize;
use std::env;

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

    for batch_id in setting.begin_batch..=setting.end_batch {
        log::info!("mock-testnet: requesting block traces of batch {batch_id}");

        let chunks = get_traces_by_block_api(&setting, batch_id).await;

        let chunks = chunks.unwrap_or_else(|e| {
            panic!("mock-testnet: failed to request API with batch-{batch_id}, err {e:?}")
        });

        match chunks {
            None => {
                log::info!("mock-testnet: finished to prove at batch-{batch_id}");
                break;
            }
            Some(chunks) => {
                for chunk in chunks {
                    let chunk_id = chunk.index;
                    log::info!("mock-testnet: handling chunk {:?}", chunk_id);

                    // fetch traces
                    let mut block_traces: Vec<BlockTrace> = vec![];
                    for block_id in chunk.start_block_number..=chunk.end_block_number {
                        log::info!("mock-testnet: requesting trace of block {block_id}");

                        let trace = provider
                            .request(
                                "scroll_getBlockTraceByNumberOrHash",
                                [format!("{block_id:#x}")],
                            )
                            .await
                            .unwrap();
                        block_traces.push(trace);
                    }

                    let witness_block = match build_block(&block_traces, batch_id, chunk_id) {
                        Ok(block) => block,
                        Err(e) => {
                            log::error!("mock-testnet: building block failed {e:?}");
                            continue;
                        }
                    };

                    let result = Prover::<SuperCircuit>::mock_prove_witness_block(&witness_block);

                    match result {
                        Ok(_) => {
                            log::info!(
                                "mock-testnet: succeeded to prove chunk {chunk_id} inside batch {batch_id}"
                            )
                        }
                        Err(err) => {
                            log::error!(
                                "mock-testnet: failed to prove chunk {chunk_id} inside batch {batch_id}:\n{err:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    log::info!("mock-testnet: end");
}

fn build_block(
    block_traces: &[BlockTrace],
    _batch_id: i64,
    chunk_id: i64,
) -> anyhow::Result<WitnessBlock> {
    let gas_total: u64 = block_traces
        .iter()
        .map(|b| b.header.gas_used.as_u64())
        .sum();
    let witness_block = block_traces_to_witness_block(block_traces)?;
    let rows = calculate_row_usage_of_witness_block(&witness_block)?;
    log::info!(
        "rows of chunk {chunk_id}(block range {:?} to {:?}):",
        block_traces.first().and_then(|b| b.header.number),
        block_traces.last().and_then(|b| b.header.number),
    );
    for r in &rows {
        log::info!("rows of {}: {}", r.name, r.row_num_real);
    }
    let row_num = rows.iter().max_by_key(|x| x.row_num_real).unwrap();
    log::info!(
        "final rows of chunk {chunk_id}: row {}({}), gas {gas_total}, gas/row {:.2}",
        row_num.row_num_real,
        row_num.name,
        gas_total as f64 / row_num.row_num_real as f64
    );
    Ok(witness_block)
}

/// Request block traces by first using rollup API to get chunk info, then fetching blocks from
/// l2geth. Return None if no more batches.
async fn get_traces_by_block_api(
    setting: &Setting,
    batch_index: i64,
) -> Result<Option<Vec<ChunkInfo>>> {
    let url = Url::parse_with_params(
        &setting.rollupscan_api_url,
        &[("batch_index", batch_index.to_string())],
    )?;

    let resp: String = reqwest::get(url).await?.text().await?;
    log::debug!("resp is {resp}");
    let resp: RollupscanResponse = serde_json::from_str(&resp)?;
    log::info!(
        "handling batch {}, chunk size {}",
        resp.batch_index,
        resp.chunks.as_ref().unwrap().len()
    );
    Ok(resp.chunks)
}

#[derive(Deserialize, Debug)]
struct RollupscanResponse {
    batch_index: usize,
    chunks: Option<Vec<ChunkInfo>>,
}

#[derive(Deserialize, Debug)]
struct ChunkInfo {
    index: i64,
    created_at: String,
    total_tx_num: i64,
    hash: String,
    start_block_number: i64,
    end_block_number: i64,
}

#[derive(Debug)]
struct Setting {
    begin_batch: i64,
    end_batch: i64,
    l2geth_api_url: String,
    rollupscan_api_url: String,
}

impl Setting {
    pub fn new() -> Self {
        let l2geth_api_url =
            env::var("L2GETH_API_URL").expect("mock-testnet: Must set env L2GETH_API_URL");
        let rollupscan_api_url = env::var("ROLLUPSCAN_API_URL");
        let rollupscan_api_url =
            rollupscan_api_url.unwrap_or_else(|_| "http://10.0.3.119:8560/api/chunks".to_string());
        let begin_batch = env::var("PROVE_BEGIN_BATCH")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(DEFAULT_BEGIN_BATCH);
        let end_batch = env::var("PROVE_END_BATCH")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(DEFAULT_END_BATCH);

        Self {
            begin_batch,
            end_batch,
            l2geth_api_url,
            rollupscan_api_url,
        }
    }
}
