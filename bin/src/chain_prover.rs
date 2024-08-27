// This tool can be used to prove scroll network blocks.
// Note: this is NOT the production prover used in scroll networks.
// Instead this is more as a testing tool.
// For production prover, see https://github.com/scroll-tech/scroll/tree/develop/prover

use integration::{
    capacity_checker::{
        ccc_by_chunk, prepare_circuit_capacity_checker, run_circuit_capacity_checker, CCCMode,
    },
    l2geth,
};
use prover::{
    aggregator,
    utils::init_env_and_log,
    zkevm::{circuit::block_traces_to_witness_block, CircuitCapacityChecker, RowUsage},
    BatchData, BlockTrace, ChunkInfo, ChunkProof, MAX_AGG_SNARKS,
};
use std::env;

mod constants;
mod prove_utils;
mod rollupscan_client;

fn warmup() {
    prepare_circuit_capacity_checker();
    log::info!("chain_prover: prepared ccc");
}

struct BatchBuilder {
    chunks: Vec<ChunkInfo>,
    batch_data: BatchData<{ MAX_AGG_SNARKS }>,
}

impl BatchBuilder {
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            batch_data: BatchData {
                num_valid_chunks: 0,
                chunk_sizes: [0u32; MAX_AGG_SNARKS],
                chunk_data: std::iter::repeat_with(Vec::new)
                    .take(MAX_AGG_SNARKS)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            },
        }
    }
    fn reset(&mut self) {
        self.chunks.clear();
        self.batch_data = BatchData {
            num_valid_chunks: 0,
            chunk_sizes: [0u32; MAX_AGG_SNARKS],
            chunk_data: std::iter::repeat_with(Vec::new)
                .take(MAX_AGG_SNARKS)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        };
    }
    fn add_chunk(&mut self, chunk: ChunkInfo) {
        let idx = self.batch_data.num_valid_chunks as usize;
        self.batch_data.chunk_sizes[idx] = chunk.tx_bytes.len() as u32;
        self.batch_data.chunk_data[idx] = chunk.tx_bytes.clone();
        self.batch_data.num_valid_chunks += 1;
        self.chunks.push(chunk);
    }
    pub fn add(&mut self, chunk: ChunkInfo) -> Option<Vec<ChunkInfo>> {
        self.add_chunk(chunk.clone());
        log::debug!(
            "BatchBuilder: checking chunk with len {}",
            self.chunks.len()
        );

        // Condition0: chunk num
        let condition0 = self.chunks.len() >= MAX_AGG_SNARKS;
        if condition0 {
            let batch = self.chunks.clone();
            self.reset();
            return Some(batch);
        }

        let batch_bytes = self.batch_data.get_batch_data_bytes();
        let blob_bytes = aggregator::eip4844::get_blob_bytes(&batch_bytes);
        let compressed_da_size = blob_bytes.len();
        let uncompressed_da_size = self
            .batch_data
            .chunk_sizes
            .iter()
            .map(|s| *s as u64)
            .sum::<u64>();
        let uncompressed_da_size_limit = BatchData::<{ MAX_AGG_SNARKS }>::n_rows_data() as u64;
        // Condition1: compressed bytes size
        let condition1 = compressed_da_size >= constants::N_BLOB_BYTES;
        // Condition2: uncompressed bytes size
        let condition2 = uncompressed_da_size > uncompressed_da_size_limit;

        let overflow = condition1 || condition2;
        if overflow {
            // pop the last chunk and emit prev chunks
            self.chunks.truncate(self.chunks.len() - 1);
            let batch = self.chunks.clone();

            self.reset();
            self.add_chunk(chunk);

            Some(batch)
        } else {
            None
        }
    }
}

struct ChunkBuilder {
    traces: Vec<BlockTrace>,
    acc_row_usage_normalized: RowUsage,
    block_limit: Option<usize>,
}

/// Same with production "chunk proposer"
impl ChunkBuilder {
    pub fn new() -> Self {
        Self {
            traces: Vec::new(),
            acc_row_usage_normalized: RowUsage::default(),
            block_limit: None,
        }
    }
    pub fn add(&mut self, trace: BlockTrace) -> Option<Vec<BlockTrace>> {
        // Condition1: block num
        if let Some(block_limit) = self.block_limit {
            if self.traces.len() + 1 == block_limit {
                // build chunk
                let mut chunk = self.traces.clone();
                chunk.push(trace.clone());
                self.traces.clear();
                return Some(chunk);
            }
        }

        // Condition2: ccc
        let ccc_result = {
            let mut checker = CircuitCapacityChecker::new();
            checker.set_light_mode(false);
            checker.estimate_circuit_capacity(trace.clone()).unwrap()
        };
        self.acc_row_usage_normalized.add(&ccc_result);
        if !self.acc_row_usage_normalized.is_ok {
            // build a chunk with PREV traces
            let chunk = self.traces.clone();
            self.traces.clear();
            self.traces.push(trace);
            self.acc_row_usage_normalized = ccc_result;
            Some(chunk)
        } else {
            self.traces.push(trace);
            None
        }
    }
}

// Construct chunk myself
async fn prove_by_block(l2geth: &l2geth::Client, begin_block: i64, end_block: i64) {
    let mut chunk_builder = ChunkBuilder::new();
    //chunk_builder.block_limit = Some(1);
    let mut batch_builder = BatchBuilder::new();
    let (begin_block, end_block) = if begin_block == 0 && end_block == 0 {
        // Blocks within last 24 hours
        let block_num = 24 * 1200;
        log::info!("use latest {block_num} blocks");
        let latest_block = l2geth.get_block_number().await.unwrap();
        (latest_block as i64 - block_num, latest_block as i64)
    } else {
        (begin_block, end_block)
    };
    let mut batch_begin_block = begin_block;
    for block_num in begin_block..=end_block {
        let trace = l2geth
        .get_block_trace_by_num(block_num, false)
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
            prove_chunk(0, chunk[0].header.number.unwrap().as_u64(), chunk.clone());
            let fast = false;
            let chunk_info = if fast {
                unimplemented!("uncomment below");
                //ChunkInfo::from_block_traces(&chunk)
            } else {
                let witness_block = block_traces_to_witness_block(chunk).unwrap();
                ChunkInfo::from_witness_block(&witness_block, false)
            };
            if let Some(batch) = batch_builder.add(chunk_info) {
                let mut padded_batch = batch.clone();
                padding_chunk(&mut padded_batch);
                let batch_data = BatchData::<{ MAX_AGG_SNARKS }>::new(batch.len(), &padded_batch);
                let compressed_da_size =
                    aggregator::eip4844::get_blob_bytes(&batch_data.get_batch_data_bytes()).len();
                log::info!(
                    "batch built: blob usage {:.3}, chunk num {}, block num {}, block range {} to {}",
                    compressed_da_size as f32 / constants::N_BLOB_BYTES as f32,
                    batch.len(),
                    block_num - batch_begin_block + 1,
                    batch_begin_block,
                    block_num,
                );
                batch_begin_block = block_num + 1;
            }
        }
    }
}

fn padding_chunk(chunks: &mut Vec<ChunkInfo>) {
    assert_ne!(chunks.len(), 0);
    assert!(chunks.len() <= MAX_AGG_SNARKS);
    if chunks.len() < MAX_AGG_SNARKS {
        log::warn!(
            "chunk len({}) < MAX_AGG_SNARKS({}), padding...",
            chunks.len(),
            MAX_AGG_SNARKS
        );
        let last_chunk = chunks.last().unwrap();
        let mut chunk_to_pad = last_chunk.clone();
        chunk_to_pad.is_padding = true;
        let take_num = MAX_AGG_SNARKS - chunks.len();
        chunks.extend(std::iter::repeat(chunk_to_pad).take(take_num));
    }
}

fn prove_chunk(batch_id: u64, chunk_id: u64, block_traces: Vec<BlockTrace>) -> Option<ChunkProof> {
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
        let ccc_modes = [CCCMode::Optimal];
        run_circuit_capacity_checker(batch_id, chunk_id, &block_traces, &ccc_modes);
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
    l2geth: &l2geth::Client,
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
            let chunk_id = chunk.index as u64;
            log::info!("chain_prover: handling chunk {:?}", chunk_id);

            let mut block_traces: Vec<BlockTrace> = vec![];
            for block_num in chunk.start_block_number..=chunk.end_block_number {
                let trace = l2geth
                        .get_block_trace_by_num(block_num, false)
                        .await
                        .unwrap_or_else(|e| {
                            panic!("chain_prover: failed to request l2geth block-trace API for batch-{batch_id} chunk-{chunk_id} block-{block_num}: {e}")
                        });

                block_traces.push(trace);
            }

            let chunk_proof = prove_chunk(batch_id as u64, chunk_id, block_traces);

            if let Some(chunk_proof) = chunk_proof {
                chunk_proofs.push(chunk_proof);
            }
        }

        #[cfg(feature = "batch-prove")]
        use prover::BatchHeader;
        #[cfg(feature = "batch-prove")]
        let batch_header = BatchHeader::<MAX_AGG_SNARKS>::default();
        #[cfg(feature = "batch-prove")]
        prove_utils::prove_batch(
            &format!("chain_prover: batch-{batch_id}"),
            chunk_proofs,
            batch_header,
        );
    }
}

// Make sure tx-by-tx light_mode=false row usage >= real row usage

async fn txtx_ccc(l2geth: &l2geth::Client, begin_block: i64, end_block: i64) {
    let (begin_block, end_block) = if begin_block == 0 && end_block == 0 {
        // Blocks within last 24 hours
        let block_num = 24 * 1200;
        log::info!("use latest {block_num} blocks");
        let latest_block = l2geth.get_block_number().await.unwrap();
        (latest_block as i64 - block_num, latest_block as i64)
    } else {
        (begin_block, end_block)
    };
    for block_num in begin_block..=end_block {
        // part1: real row usage
        let block_num = block_num as u64;
        let batch_id = block_num;
        let chunk_id = block_num;
        let trace = l2geth
        .get_block_trace_by_num(block_num as i64, false)
        .await
        .unwrap_or_else(|e| {
            panic!("chain_prover: failed to request l2geth block-trace API for block-{block_num}: {e}")
        });
        let tx_traces = l2geth
        .get_txbytx_trace_by_num(block_num as i64)
        .await
        .unwrap_or_else(|e| {
            panic!("chain_prover: failed to request l2geth block-trace API for block-{block_num}: {e}")
        });
        let (real_usage, t) = ccc_by_chunk(batch_id, chunk_id, &[trace]);

        // part2: tx by tx row usage
        let tx_num = tx_traces.len();
        let mut checker = CircuitCapacityChecker::new();
        checker.light_mode = false;
        let start_time = std::time::Instant::now();
        for tx in tx_traces {
            checker.estimate_circuit_capacity(tx).unwrap();
        }
        let row_usage = checker.get_acc_row_usage(false);
        let avg_ccc_time = start_time.elapsed().as_millis() / tx_num as u128;

        // part3: pretty print
        log::info!("circuit\ttxbytx\tblock\tblock-{block_num}");
        for i in 0..real_usage.row_usage_details.len() {
            let r1 = row_usage.row_usage_details[i].row_number;
            let r2 = real_usage.row_usage_details[i].row_number;
            // FIXME: the "1" of bytecode circuit
            assert!(r1 + 1 >= r2);
            let show_name: String = row_usage.row_usage_details[i]
                .name
                .chars()
                .take(7)
                .collect();
            log::info!("{}\t{}\t{}", show_name, r1, r2);
        }
        log::info!("{}\t{}\t{}", "avgtxms", t.as_millis(), avg_ccc_time);
    }
}

#[tokio::main]
async fn main() {
    init_env_and_log("chain_prover");

    log::info!("chain_prover: BEGIN");

    let setting = Setting::new();
    log::info!("chain_prover: setting = {setting:?}");

    warmup();

    let l2geth = l2geth::Client::new("chain_prover", &setting.l2geth_api_url)
        .unwrap_or_else(|e| panic!("chain_prover: failed to initialize ethers Provider: {e}"));
    let rollupscan = rollupscan_client::Client::new("chain_prover", &setting.rollupscan_api_url);

    let test_mode = &setting.test_mode;

    if test_mode == "batch_prove" {
        prove_by_batch(&l2geth, &rollupscan, setting.begin_batch, setting.end_batch).await
    } else if test_mode == "block_prove" {
        prove_by_block(&l2geth, setting.begin_block, setting.end_block).await
    } else if test_mode == "txtx_ccc" {
        txtx_ccc(&l2geth, setting.begin_block, setting.end_block).await
    } else {
        // Handle unknown test_mode here
        unimplemented!("{test_mode}");
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
    test_mode: String,
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
        let test_mode = env::var("TEST_MODE")
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
            test_mode,
        }
    }
}
