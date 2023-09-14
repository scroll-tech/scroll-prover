use itertools::Itertools;
use prover::{
    zkevm::{CircuitCapacityChecker, RowUsage, SubCircuitRowUsage, circuit::calculate_row_usage_of_witness_block},
    BlockTrace, WitnessBlock,
};
use std::{time::Duration, slice};
use zkevm_circuits::evm_circuit::ExecutionState;

pub fn prepare_circuit_capacity_checker() {
    // Force evm_circuit::param::EXECUTION_STATE_HEIGHT_MAP to be initialized.
    let mulmod_height = ExecutionState::MULMOD.get_step_height();
    log::debug!("mulmod_height {mulmod_height}");
    debug_assert_eq!(mulmod_height, 18);
}

// Return average ccc time for each tx.
pub fn run_circuit_capacity_checker(
    batch_id: i64,
    chunk_id: i64,
    blocks: &[BlockTrace],
    block_modes: Vec<bool>,
    by_block: bool,
) -> Duration {

    // as is l2geth
    // let (each_tx_ccc_result, avg_each_tx_time) = get_ccc_result_of_chunk(chunk_id, blocks, true, true);

    let (each_tx_ccc_result, avg_each_tx_time) = get_ccc_result_of_chunk(chunk_id, blocks, by_block, false);

    for light_mode in block_modes {
        let whole_block_ccc_result = get_ccc_result_by_whole_block(chunk_id, light_mode, blocks);
        check_each_tx_and_whole_block_ccc_results(
            chunk_id,
            &each_tx_ccc_result,
            &whole_block_ccc_result,
            light_mode,
        );
    }

    avg_each_tx_time
}

/// print analyze results
pub fn pretty_print_row_usage(
    rows: &RowUsage,
    block_traces: &[BlockTrace],
    chunk_id: i64,
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
    let row_num = rows
        .row_usage_details
        .iter()
        .max_by_key(|x| x.row_number)
        .unwrap();
    log::info!(
        "final rows of chunk {chunk_id}(block range {:?} to {:?}): row {}(bottleneck:{},mode:{mode}), gas {gas_total}, gas/row {:.2}",
        block_traces.first().and_then(|b| b.header.number),
        block_traces.last().and_then(|b| b.header.number),
        row_num.row_number,
        row_num.name,
        gas_total as f64 / row_num.row_number as f64
    );
    //debug_assert!(row_num.row_number <= 1_000_000);
}

fn ccc_block_whole_block(checker: &mut CircuitCapacityChecker, block_idx: usize, block: &BlockTrace) {
    checker.estimate_circuit_capacity(slice::from_ref(block)).unwrap();
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
            header: block.header.clone(),
            start_l1_queue_index: block.start_l1_queue_index,
            tx_storage_trace: vec![], // not used
        };
        log::debug!("calling estimate_circuit_capacity");
        let results = checker.estimate_circuit_capacity(&[tx_trace]).unwrap();
        log::info!(
            "after {}th block {}th tx: {:#?}",
            block_idx,
            tx_idx,
            results
        );
    }
}

// Return row-usage and average ccc time for each tx.
fn get_ccc_result_of_chunk(chunk_id: i64, blocks: &[BlockTrace], by_block: bool, norm: bool) -> (RowUsage, Duration) {
    log::info!(
        "estimating circuit rows tx by tx, tx num {}",
        blocks
            .iter()
            .map(|b| b.execution_results.len())
            .sum::<usize>(),
    );

    let mut checker = CircuitCapacityChecker::new();
    checker.light_mode = true;
    if !checker.light_mode && !by_block {
        unimplemented!("!checker.light_mode && !by_block")
    }

    let start_time = std::time::Instant::now();

    let disable_chunk_opt = true; // like l2geth
    let mut tx_num = 0;
    let mut acc_row_usage_normalized = RowUsage::default();
    let mut acc_row_usage_raw = RowUsage::default();
    for (block_idx, block) in blocks.iter().enumerate() {
        if disable_chunk_opt {
            checker.reset();
        }
        if by_block {
            ccc_block_whole_block(&mut checker, block_idx, block);
        } else {
            ccc_block_tx_by_tx(&mut checker, block_idx, block);
        }
        let is_last = block_idx == blocks.len() - 1;
        if disable_chunk_opt || is_last {
            let block_result_raw = checker.get_acc_row_usage(false);
            if disable_chunk_opt {
                log::info!(
                "block ccc result(block {}): {:?}",
                block.header.number.unwrap().as_u64(),
                if norm {
                    block_result_raw.normalize()
                } else {
                    block_result_raw.clone()
                }
            );
                pretty_print_row_usage(&block_result_raw, std::slice::from_ref(block), chunk_id, "inner");
            } else {
                //pretty_print_row_usage(&block_result_raw, std::slice::from_ref(block), chunk_id, "inner");
            }
            acc_row_usage_raw.add(&block_result_raw);
            acc_row_usage_normalized.add(&block_result_raw.normalize());
        }
        tx_num += block.transactions.len();
    }
    log::info!("capacity_checker test done");
    pretty_print_row_usage(if norm {
        &acc_row_usage_normalized
    } else {
        &acc_row_usage_raw
    }, blocks, chunk_id, "tx-raw");
    //pretty_print_row_usage(&acc_row_usage_normalized, blocks, chunk_id, "tx-norm");

    let avg_ccc_time = start_time.elapsed().as_millis() / tx_num as u128;
    log::info!("avg time each tx: {avg_ccc_time}ms",);

    (
        acc_row_usage_raw,
        Duration::from_millis(avg_ccc_time as u64),
    )
}

fn get_ccc_result_by_whole_block(
    chunk_id: i64,
    light_mode: bool,
    blocks: &[BlockTrace],
) -> RowUsage {
    log::info!("estimating circuit rows whole block, light_mode {light_mode}");
    let mut checker = CircuitCapacityChecker::new();
    checker.light_mode = light_mode;

    checker.estimate_circuit_capacity(blocks).unwrap();
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

fn check_each_tx_and_whole_block_ccc_results(
    chunk_id: i64,
    each_tx_ccc_result: &RowUsage,
    whole_block_ccc_result: &RowUsage,
    light_mode: bool,
) {
    for (t, b) in each_tx_ccc_result
        .row_usage_details
        .iter()
        .zip_eq(whole_block_ccc_result.row_usage_details.iter())
    {
        log::info!(
            "{}: {}(tx) vs {}(block-light-{light_mode}), over estimate ratio {}",
            t.name,
            t.row_number,
            b.row_number,
            t.row_number as f64 / b.row_number as f64
        );
        assert!(t.row_number >= b.row_number);
    }
}


/// most accurate
pub fn ccc_by_chunk(
    block_traces: &[BlockTrace],
    batch_id: i64,
    chunk_id: i64,
    witness_block: &WitnessBlock,
) {
    log::info!("mock-testnet: run ccc for batch-{batch_id} chunk-{chunk_id}");
    let rows = calculate_row_usage_of_witness_block(&witness_block).unwrap();
    let row_usage_details: Vec<SubCircuitRowUsage> = rows
        .into_iter()
        .map(|x| SubCircuitRowUsage {
            name: x.name,
            row_number: x.row_num_real,
        })
        .collect_vec();
    let row_usage = RowUsage::from_row_usage_details(row_usage_details);
    pretty_print_row_usage(&row_usage, block_traces, chunk_id, "chunk");
}
