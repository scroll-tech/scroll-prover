use itertools::Itertools;
use prover::{
    zkevm::{
        circuit::{block_traces_to_witness_block, calculate_row_usage_of_witness_block},
        CircuitCapacityChecker, RowUsage, SubCircuitRowUsage,
    },
    zkevm_circuits::evm_circuit::ExecutionState,
    BlockTrace,
};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CCCMode {
    Optimal,
    Siger,
    FollowerLight,
    FollowerFull,
}

pub fn prepare_circuit_capacity_checker() {
    // Force evm_circuit::param::EXECUTION_STATE_HEIGHT_MAP to be initialized.
    let mulmod_height = ExecutionState::MULMOD.get_step_height();
    log::debug!("mulmod_height {mulmod_height}");
    //debug_assert_eq!(mulmod_height, 18);
}

// Return average ccc time for each tx.
pub fn run_circuit_capacity_checker(
    batch_id: u64,
    chunk_id: u64,
    block_traces: &[BlockTrace],
    modes: &[CCCMode],
) -> Option<Duration> {
    let results = modes
        .iter()
        .map(|mode| {
            (
                *mode,
                match mode {
                    CCCMode::Optimal => ccc_by_chunk(batch_id, chunk_id, block_traces),
                    CCCMode::Siger => ccc_as_signer(chunk_id, block_traces),
                    CCCMode::FollowerLight => ccc_as_follower_light(chunk_id, block_traces),
                    CCCMode::FollowerFull => ccc_as_follower_full(chunk_id, block_traces),
                },
            )
        })
        .collect_vec();

    if results.len() > 1 {
        for idx in 1..results.len() {
            compare_ccc_results(
                chunk_id,
                &results[0].1 .0,
                results[0].0,
                &results[idx].1 .0,
                results[idx].0,
            );
        }
    }

    results
        .into_iter()
        .find(|(mode, _)| *mode == CCCMode::Siger)
        .map(|(_, (_, t))| t)
}

/// print analyze results
pub fn pretty_print_row_usage(
    rows: &RowUsage,
    block_traces: &[BlockTrace],
    chunk_id: u64,
    mode: &str,
) {
    let gas_total: u64 = block_traces
        .iter()
        .map(|b| b.header.gas_used.as_u64())
        .sum();
    log::info!(
        "rows of chunk {chunk_id}(block range {:?} to {:?}):",
        block_traces.first().and_then(|b| b.header.number),
        block_traces.last().and_then(|b| b.header.number),
    );
    for r in &rows.row_usage_details {
        log::info!("rows of {} : {}", r.name, r.row_number);
    }
    let row_num = bottleneck(rows);
    log::info!(
        "final rows of chunk {chunk_id}(block range {:?} to {:?}): row {}({},mode:{mode}), gas {gas_total}, gas/row {:.2}",
        block_traces.first().and_then(|b| b.header.number),
        block_traces.last().and_then(|b| b.header.number),
        row_num.row_number,
        row_num.name,
        gas_total as f64 / row_num.row_number as f64
    );
    if !mode.contains("signer") {
        debug_assert!(row_num.row_number <= 1_000_000);
    }
}

fn bottleneck(rows: &RowUsage) -> SubCircuitRowUsage {
    let mut r = rows
        .row_usage_details
        .iter()
        .max_by_key(|x| x.row_number)
        .unwrap()
        .clone();
    // adhoc...
    r.name = format!("bottleneck-{}", r.name);
    r
}

fn ccc_block_whole_block(
    checker: &mut CircuitCapacityChecker,
    _block_idx: usize,
    block: &BlockTrace,
) {
    checker.estimate_circuit_capacity(block.clone()).unwrap();
}

fn ccc_block_tx_by_tx(checker: &mut CircuitCapacityChecker, block_idx: usize, block: &BlockTrace) {
    for tx_idx in 0..block.transactions.len() {
        log::info!("processing {}th block {}th tx", block_idx, tx_idx);
        #[rustfmt::skip]
        /*  
        The capacity_checker is expected to be run inside sequencer, where we don't have the traces of blocks, instead we only have traces of tx.
        For the "tx_trace":
            transactions: 
                the tx itself. For compatibility reasons, transactions is a vector of len 1 now.   
            execution_results: 
                tx execution trace. Similar with above, it is also of len 1 vevtor.   
            storage_trace: 
                storage_trace is prestate + siblings(or proofs) of touched storage_slots and accounts of this tx.
        */

        let tx_trace = BlockTrace {
            transactions: vec![block.transactions[tx_idx].clone()],
            execution_results: vec![block.execution_results[tx_idx].clone()],
            storage_trace: block.tx_storage_trace[tx_idx].clone(),
            chain_id: block.chain_id,
            coinbase: block.coinbase.clone(),
            codes: block.codes.clone(),
            header: block.header.clone(),
            start_l1_queue_index: block.start_l1_queue_index,
            ..Default::default()
        };
        log::debug!("calling estimate_circuit_capacity");
        let results = checker.estimate_circuit_capacity(tx_trace).unwrap();
        log::info!("after {}th block {}th tx: {:?}", block_idx, tx_idx, results);
    }
}

// Return row-usage and average ccc time for each tx.
fn get_ccc_result_of_chunk(
    chunk_id: u64,
    blocks: &[BlockTrace],
    by_block: bool, // by block instead of by tx
    norm: bool,
    light_mode: bool,
    tag: &str,
) -> (RowUsage, Duration) {
    log::info!(
        "estimating circuit rows tx by tx, tx num {}",
        blocks
            .iter()
            .map(|b| b.execution_results.len())
            .sum::<usize>(),
    );

    let mut checker = CircuitCapacityChecker::new();
    checker.light_mode = light_mode;

    if !checker.light_mode && !by_block {
        unimplemented!("!checker.light_mode && !by_block")
    }

    let start_time = std::time::Instant::now();

    let mut tx_num = 0;
    let mut acc_row_usage_normalized = RowUsage::default();
    let mut acc_row_usage_raw = RowUsage::default();
    for (block_idx, block) in blocks.iter().enumerate() {
        checker.reset();

        if by_block {
            ccc_block_whole_block(&mut checker, block_idx, block);
        } else {
            ccc_block_tx_by_tx(&mut checker, block_idx, block);
        }

        let block_result_raw = checker.get_acc_row_usage(false);

        log::info!(
            "block ccc result(block {}): {:?}",
            block.header.number.unwrap().as_u64(),
            if norm {
                block_result_raw.normalize()
            } else {
                block_result_raw.clone()
            }
        );
        pretty_print_row_usage(
            &block_result_raw,
            std::slice::from_ref(block),
            chunk_id,
            "inner",
        );
        acc_row_usage_raw.add(&block_result_raw);
        acc_row_usage_normalized.add(&block_result_raw.normalize());

        tx_num += block.transactions.len();
    }
    log::info!("capacity_checker test done");
    pretty_print_row_usage(&acc_row_usage_raw, blocks, chunk_id, tag);
    let avg_ccc_time = start_time.elapsed().as_millis() / tx_num as u128;
    log::info!("avg time each tx: {avg_ccc_time}ms, mode {tag}");

    (
        acc_row_usage_raw,
        Duration::from_millis(avg_ccc_time as u64),
    )
}

#[allow(dead_code)]
fn get_ccc_result_by_whole_block(
    chunk_id: u64,
    light_mode: bool,
    blocks: &[BlockTrace],
) -> RowUsage {
    log::info!("estimating circuit rows whole block, light_mode {light_mode}");
    let mut checker = CircuitCapacityChecker::new();
    checker.light_mode = light_mode;

    for block in blocks {
        checker.estimate_circuit_capacity(block.clone()).unwrap();
    }
    let ccc_result = checker.get_acc_row_usage(false);
    pretty_print_row_usage(
        &ccc_result,
        blocks,
        chunk_id,
        if light_mode {
            "block-light"
        } else {
            "block-full"
        },
    );

    ccc_result
}

fn compare_ccc_results(
    chunk_id: u64,
    lhs: &RowUsage,
    lhs_mode: CCCMode,
    rhs: &RowUsage,
    rhs_mode: CCCMode,
) {
    for (l, r) in lhs
        .row_usage_details
        .iter()
        .zip_eq(rhs.row_usage_details.iter())
        .chain(std::iter::once((&bottleneck(lhs), &bottleneck(rhs))))
    {
        log::info!(
            "chunk {chunk_id}: {lhs_mode:?} {} {} vs {rhs_mode:?} {} {}. r/l: {}",
            l.name,
            l.row_number,
            r.name,
            r.row_number,
            r.row_number as f64 / l.row_number as f64
        );
        if lhs_mode == CCCMode::Optimal {
            // FIXME the "+1", bytecode
            assert!(r.row_number + 1 >= l.row_number);
        }
    }
}

/// most accurate, optimal
pub fn ccc_by_chunk(
    batch_id: u64,
    chunk_id: u64,
    block_traces: &[BlockTrace],
) -> (RowUsage, Duration) {
    log::info!("ccc_by_chunk: run ccc for batch-{batch_id} chunk-{chunk_id}");

    let start_time = std::time::Instant::now();
    let witness_block = block_traces_to_witness_block(Vec::from(block_traces)).unwrap();
    let rows = calculate_row_usage_of_witness_block(&witness_block).unwrap();
    let row_usage = RowUsage::from_row_usage_details(rows);
    pretty_print_row_usage(&row_usage, block_traces, chunk_id, "chunk-opt");

    let avg_ccc_time_per_tx = Duration::from_millis(
        start_time.elapsed().as_millis() as u64 / witness_block.txs.len() as u64,
    );

    (row_usage, avg_ccc_time_per_tx)
}

pub fn ccc_as_signer(chunk_id: u64, blocks: &[BlockTrace]) -> (RowUsage, Duration) {
    get_ccc_result_of_chunk(chunk_id, blocks, false, false, true, "chunk-signer")
}

/// current stats inside db
pub fn ccc_as_follower_light(chunk_id: u64, blocks: &[BlockTrace]) -> (RowUsage, Duration) {
    get_ccc_result_of_chunk(chunk_id, blocks, true, false, true, "chunk-f-l")
}

pub fn ccc_as_follower_full(chunk_id: u64, blocks: &[BlockTrace]) -> (RowUsage, Duration) {
    get_ccc_result_of_chunk(chunk_id, blocks, true, false, false, "chunk-f-f")
}

pub fn ccc_txbytx_full(tx_traces: &[BlockTrace]) -> (RowUsage, Duration) {
    let tx_num = tx_traces.len();
    let mut checker = CircuitCapacityChecker::new();
    checker.light_mode = false;
    let start_time = std::time::Instant::now();
    for tx in tx_traces {
        checker.estimate_circuit_capacity(tx.clone()).unwrap();
    }
    let row_usage = checker.get_acc_row_usage(false);
    let avg_ccc_time = start_time.elapsed().as_millis() / tx_num as u128;
    (row_usage, Duration::from_millis(avg_ccc_time as u64))
}

pub fn compare_txbytx(tx_traces: &[BlockTrace], trace: &BlockTrace, block_num: u64) {
    let batch_id = block_num;
    let chunk_id = block_num;
    let (real_usage, t) = ccc_by_chunk(batch_id, chunk_id, &[trace.clone()]);

    // part2: tx by tx row usage
    let (row_usage, avg_ccc_time) = ccc_txbytx_full(&tx_traces);

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
    log::info!(
        "{}\t{}\t{}",
        "avgtxms",
        t.as_millis(),
        avg_ccc_time.as_millis()
    );
}
