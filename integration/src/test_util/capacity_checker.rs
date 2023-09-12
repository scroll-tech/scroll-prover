use itertools::Itertools;
use prover::{
    zkevm::{CircuitCapacityChecker, RowUsage},
    BlockTrace,
};
use zkevm_circuits::evm_circuit::ExecutionState;

pub fn prepare_circuit_capacity_checker() {
    // Force evm_circuit::param::EXECUTION_STATE_HEIGHT_MAP to be initialized.
    let mulmod_height = ExecutionState::MULMOD.get_step_height();
    log::debug!("mulmod_height {mulmod_height}");
    debug_assert_eq!(mulmod_height, 18);
}

pub fn run_circuit_capacity_checker(blocks: &[BlockTrace]) {
    let each_tx_ccc_result = get_ccc_result_by_each_tx(blocks);

    for light_mode in [true, false] {
        let whole_block_ccc_result = get_ccc_result_by_whole_block(light_mode, blocks);
        check_each_tx_and_whole_block_ccc_results(&each_tx_ccc_result, &whole_block_ccc_result);
    }
}

fn get_ccc_result_by_each_tx(blocks: &[BlockTrace]) -> RowUsage {
    log::info!(
        "estimating circuit rows tx by tx, tx num {}",
        blocks
            .iter()
            .map(|b| b.execution_results.len())
            .sum::<usize>(),
    );

    let mut checker = CircuitCapacityChecker::new();
    // checker.light_mode = false;

    let start_time = std::time::Instant::now();

    let mut tx_num = 0;
    for (block_idx, block) in blocks.iter().enumerate() {
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
            let results = checker.estimate_circuit_capacity(&[tx_trace]);
            log::info!(
                "after {}th block {}th tx: {:#?}",
                block_idx,
                tx_idx,
                results
            );
        }
        tx_num += block.transactions.len();
    }
    log::info!("capacity_checker test done");
    let ccc_result = checker.get_acc_row_usage(false);
    log::info!(
        "ccc result tx by tx {:#?}, after normalize {:#?}",
        ccc_result,
        ccc_result.normalize()
    );

    let avg_ccc_time = start_time.elapsed().as_millis() as usize / tx_num;
    log::info!("avg time each tx: {avg_ccc_time}ms",);
    assert!(avg_ccc_time < 100);

    ccc_result
}

fn get_ccc_result_by_whole_block(light_mode: bool, blocks: &[BlockTrace]) -> RowUsage {
    log::info!("estimating circuit rows whole block, light_mode {light_mode}");
    let mut checker = CircuitCapacityChecker::new();
    checker.light_mode = light_mode;

    checker.estimate_circuit_capacity(blocks).unwrap();
    let ccc_result = checker.get_acc_row_usage(false);
    log::info!(
        "ccc result whole block {:#?}, after normalize {:#?}",
        ccc_result,
        ccc_result.normalize()
    );

    ccc_result
}

fn check_each_tx_and_whole_block_ccc_results(
    each_tx_ccc_result: &RowUsage,
    whole_block_ccc_result: &RowUsage,
) {
    for (t, b) in each_tx_ccc_result
        .row_usage_details
        .iter()
        .zip_eq(whole_block_ccc_result.row_usage_details.iter())
    {
        log::info!(
            "{}: {}(tx) vs {}(block), over estimate ratio {}",
            t.name,
            t.row_number,
            b.row_number,
            t.row_number as f64 / b.row_number as f64
        );
        assert!(t.row_number >= b.row_number);
    }
}
