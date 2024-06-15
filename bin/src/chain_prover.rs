// This tool can be used to prove scroll network blocks.
// Note: this is NOT the production prover used in scroll networks.
// Instead this is more as a testing tool.
// For production prover, see https://github.com/scroll-tech/scroll/tree/develop/prover

use integration::capacity_checker::{
    prepare_circuit_capacity_checker, run_circuit_capacity_checker,
};
use prover::{
    utils::init_env_and_log,
    zkevm::{circuit::block_traces_to_witness_block, CircuitCapacityChecker, RowUsage},
    BatchData, BlockTrace, ChunkInfo, ChunkProof, MAX_AGG_SNARKS,
};
use std::env;

mod l2geth_client;
mod prove_utils;
mod rollupscan_client;

fn warmup() {
    prepare_circuit_capacity_checker();
    log::info!("chain_prover: prepared ccc");
}

#[derive(Default)]
struct ConstantNumBatchBuilder {
    chunks: Vec<ChunkInfo>,
}

impl ConstantNumBatchBuilder {
    pub fn add(&mut self, chunk: ChunkInfo) -> Option<Vec<ChunkInfo>> {
        self.chunks.push(chunk);
        log::debug!("ConstantNumBatchBuilder chunks len {}", self.chunks.len());
        if self.chunks.len() == MAX_AGG_SNARKS {
            let batch = self.chunks.clone();
            self.chunks.clear();
            return Some(batch);
        } else {
            return None;
        }
    }
}

struct SimpleChunkBuilder {
    traces: Vec<BlockTrace>,
    acc_row_usage_normalized: RowUsage,
}

/// Same with production "chunk proposer"
impl SimpleChunkBuilder {
    pub fn new() -> Self {
        Self {
            traces: Vec::new(),
            acc_row_usage_normalized: RowUsage::default(),
        }
    }
    pub fn add(&mut self, trace: BlockTrace) -> Option<Vec<BlockTrace>> {
        let mut checker = CircuitCapacityChecker::new();
        checker.set_light_mode(false);
        let ccc_result = checker.estimate_circuit_capacity(trace.clone()).unwrap();
        self.acc_row_usage_normalized.add(&ccc_result);
        if !self.acc_row_usage_normalized.is_ok {
            // build a chunk with PREV traces
            let chunk = self.traces.clone();
            self.traces.clear();
            self.traces.push(trace);
            self.acc_row_usage_normalized = ccc_result;
            return Some(chunk);
        } else {
            self.traces.push(trace);
            return None;
        }
    }
}

// Construct chunk myself
async fn prove_by_block(l2geth: &l2geth_client::Client, begin_block: i64, end_block: i64) {
    let mut chunk_builder = SimpleChunkBuilder::new();
    let mut batch_builder = ConstantNumBatchBuilder::default();
    let (begin_block, end_block) = if begin_block == 0 && end_block == 0 {
        // Blocks within last hour
        log::info!("use latest 1200 blocks");
        let latest_block = l2geth.get_block_number().await.unwrap();
        (latest_block as i64 - 1200, latest_block as i64)
    } else {
        (begin_block, end_block)
    };
    let mut batch_begin_block = begin_block;
    for block_num in begin_block..=end_block {
        let trace = l2geth
        .get_block_trace_by_num(block_num)
        .await
        .unwrap_or_else(|e| {
            panic!("chain_prover: failed to request l2geth block-trace API for block-{block_num}: {e}")
        });
        log::info!(
            "fetch trace done. begin {} end {} cur {}, progress {:.1}%",
            begin_block,
            end_block,
            block_num,
            100.0 * (block_num - begin_block + 1) as f32 / (end_block - begin_block + 1) as f32
        );
        if let Some(chunk) = chunk_builder.add(trace) {
            prove_chunk(0, 0, chunk.clone());
            let witness_block = block_traces_to_witness_block(chunk).unwrap();
            let chunk_info = ChunkInfo::from_witness_block(&witness_block, false);
            if let Some(batch) = batch_builder.add(chunk_info) {
                let batch_data = BatchData::<{ MAX_AGG_SNARKS }>::new(MAX_AGG_SNARKS, &batch);
                let _ = batch_data.get_encoded_batch_data_bytes();
                log::info!(
                    "batch data: batch block range {} to {}, block num {}",
                    batch_begin_block,
                    block_num,
                    block_num - batch_begin_block + 1
                );
                batch_begin_block = block_num + 1;
            }
        }
    }
}

fn prove_chunk(batch_id: i64, chunk_id: i64, block_traces: Vec<BlockTrace>) -> Option<ChunkProof> {
    let total_gas: u64 = block_traces
        .iter()
        .map(|b| b.header.gas_used.as_u64())
        .sum();
    log::info!(
        "proving chunk with {} blocks, total gas {}",
        block_traces.len(),
        total_gas
    );

    if env::var("CIRCUIT").unwrap_or_default() == "none" {
        return None;
    }
    if env::var("CIRCUIT").unwrap_or_default() == "ccc" {
        run_circuit_capacity_checker(batch_id, chunk_id, &block_traces);
        return None;
    }

    let chunk_proof = prove_utils::prove_chunk(
        &format!("chain_prover: batch-{batch_id} chunk-{chunk_id}"),
        block_traces,
    );
    log::info!("proving chunk done");
    chunk_proof
}

// Use constructed chunk/batch info from coordinator
async fn prove_by_batch(
    l2geth: &l2geth_client::Client,
    rollupscan: &rollupscan_client::Client,
    begin_batch: i64,
    end_batch: i64,
) {
    for batch_id in begin_batch..=end_batch {
        let chunks = rollupscan
                .get_chunk_info_by_batch_index(batch_id)
                .await
                .unwrap_or_else(|e| {
                    panic!("chain_prover: failed to request rollupscan chunks API for batch-{batch_id}: {e}")
                });

        if chunks.is_none() {
            log::warn!("chain_prover: no chunks in batch-{batch_id}");
            continue;
        }

        let mut chunk_proofs = vec![];
        for chunk in chunks.unwrap() {
            let chunk_id = chunk.index;
            log::info!("chain_prover: handling chunk {:?}", chunk_id);

            let mut block_traces: Vec<BlockTrace> = vec![];
            for block_num in chunk.start_block_number..=chunk.end_block_number {
                let trace = l2geth
                        .get_block_trace_by_num(block_num)
                        .await
                        .unwrap_or_else(|e| {
                            panic!("chain_prover: failed to request l2geth block-trace API for batch-{batch_id} chunk-{chunk_id} block-{block_num}: {e}")
                        });

                block_traces.push(trace);
            }

            let chunk_proof = prove_chunk(batch_id, chunk_id, block_traces);

            if let Some(chunk_proof) = chunk_proof {
                chunk_proofs.push(chunk_proof);
            }
        }

        #[cfg(feature = "batch-prove")]
        prove_utils::prove_batch(&format!("chain_prover: batch-{batch_id}"), chunk_proofs);
    }
}
#[tokio::main]
async fn main() {
    init_env_and_log("chain_prover");

    log::info!("chain_prover: BEGIN");

    let setting = Setting::new();
    log::info!("chain_prover: setting = {setting:?}");

    warmup();

    let l2geth = l2geth_client::Client::new("chain_prover", &setting.l2geth_api_url)
        .unwrap_or_else(|e| panic!("chain_prover: failed to initialize ethers Provider: {e}"));
    let rollupscan = rollupscan_client::Client::new("chain_prover", &setting.rollupscan_api_url);

    if setting.batch_mode {
        prove_by_batch(&l2geth, &rollupscan, setting.begin_batch, setting.end_batch).await;
    } else {
        prove_by_block(&l2geth, setting.begin_block, setting.end_block).await;
    }

    log::info!("chain_prover: END");
}

// TODO: change this to clap cli args
#[derive(Debug)]
struct Setting {
    begin_batch: i64,
    end_batch: i64,
    begin_block: i64,
    end_block: i64,
    l2geth_api_url: String,
    rollupscan_api_url: String,
    batch_mode: bool,
}

impl Setting {
    pub fn new() -> Self {
        let l2geth_api_url =
            env::var("L2GETH_API_URL").unwrap_or("http://127.0.0.1:8545".to_string());
        let rollupscan_api_url = env::var("ROLLUPSCAN_API_URL");
        let rollupscan_api_url = rollupscan_api_url.unwrap_or_default();
        let begin_batch = env::var("PROVE_BEGIN_BATCH")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or_default();
        let end_batch = env::var("PROVE_END_BATCH")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or_default();
        let begin_block = env::var("PROVE_BEGIN_BLOCK")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or_default();
        let end_block = env::var("PROVE_END_BLOCK")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or_default();
        let batch_mode = env::var("BATCH_MODE")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or_default();

        Self {
            begin_batch,
            end_batch,
            begin_block,
            end_block,
            l2geth_api_url,
            rollupscan_api_url,
            batch_mode,
        }
    }
}
