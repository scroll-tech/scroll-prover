use anyhow::Result;
use integration::test_util::{prepare_circuit_capacity_checker, run_circuit_capacity_checker};
use prover::{
    utils::init_env_and_log, zkevm::circuit::block_traces_to_witness_block, BlockTrace,
    WitnessBlock,
};
use std::env;

mod l2geth;
mod prove;
mod rollupscan;

const DEFAULT_BEGIN_BATCH: i64 = 1;
const DEFAULT_END_BATCH: i64 = i64::MAX;

#[tokio::main]
async fn main() {
    init_env_and_log("mock_testnet");

    log::info!("mock-testnet: BEGIN");

    let setting = Setting::new();
    log::info!("mock-testnet: setting = {setting:?}");

    prepare_circuit_capacity_checker();
    log::info!("mock-testnet: prepared ccc");

    let l2geth = l2geth::Client::new("mock-testnet", &setting.l2geth_api_url)
        .unwrap_or_else(|e| panic!("mock-testnet: failed to initialize ethers Provider: {e}"));
    let rollupscan = rollupscan::Client::new("mock-testnet", &setting.rollupscan_api_url);

    for batch_id in setting.begin_batch..=setting.end_batch {
        let chunks = rollupscan
            .get_chunk_info_by_batch_index(batch_id)
            .await
            .unwrap_or_else(|e| {
                panic!("mock-testnet: failed to request rollupscan chunks API for batch-{batch_id}: {e}")
            });

        if chunks.is_none() {
            log::warn!("mock-testnet: no chunks in batch-{batch_id}");
            continue;
        }

        let mut chunk_proofs = vec![];
        for chunk in chunks.unwrap() {
            let chunk_id = chunk.index;
            log::info!("mock-testnet: handling chunk {:?}", chunk_id);

            let mut block_traces: Vec<BlockTrace> = vec![];
            for block_num in chunk.start_block_number..=chunk.end_block_number {
                let trace = l2geth
                    .get_block_trace_by_num(block_num)
                    .await
                    .unwrap_or_else(|e| {
                        panic!("mock-testnet: failed to request l2geth block-trace API for batch-{batch_id} chunk-{chunk_id} block-{block_num}: {e}")
                    });

                block_traces.push(trace);
            }

            let witness_block = match build_block(&block_traces, batch_id, chunk_id) {
                Ok(block) => block,
                Err(e) => {
                    log::error!("mock-testnet: building block failed {e:?}");
                    continue;
                }
            };
            if env::var("CIRCUIT").unwrap_or_default() == "ccc" {
                continue;
            }

            let chunk_proof = prove::prove_chunk(
                &format!("mock-testnet: batch-{batch_id} chunk-{chunk_id}"),
                &witness_block,
            );

            if let Some(chunk_proof) = chunk_proof {
                chunk_proofs.push(chunk_proof);
            }
        }

        #[cfg(feature = "batch-prove")]
        prove::prove_batch(&format!("mock-testnet: batch-{batch_id}"), chunk_proofs);
    }

    log::info!("mock-testnet: END");
}

fn build_block(block_traces: &[BlockTrace], batch_id: i64, chunk_id: i64) -> Result<WitnessBlock> {
    let witness_block = block_traces_to_witness_block(Vec::from(block_traces))?;
    run_circuit_capacity_checker(batch_id, chunk_id, block_traces, &witness_block);
    Ok(witness_block)
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
