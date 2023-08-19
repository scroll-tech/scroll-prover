use super::{
    TargetCircuit, AUTO_TRUNCATE, CHAIN_ID, MAX_BYTECODE, MAX_CALLDATA, MAX_EXP_STEPS,
    MAX_INNER_BLOCKS, MAX_KECCAK_ROWS, MAX_MPT_ROWS, MAX_PRECOMPILE_EC_ADD, MAX_PRECOMPILE_EC_MUL,
    MAX_PRECOMPILE_EC_PAIRING, MAX_RWS, MAX_TXS,
};
use crate::config::INNER_DEGREE;
use anyhow::{bail, Result};
use bus_mapping::{
    circuit_input_builder::{CircuitInputBuilder, CircuitsParams, PrecompileEcParams,},
};
use eth_types::{ToBigEndian, H256};
use halo2_proofs::halo2curves::bn256::Fr;
use is_even::IsEven;
use itertools::Itertools;
use std::{
    collections::{hash_map::Entry, HashMap},
    time::Instant,
};
use types::eth::{BlockTrace, StorageTrace};
use zkevm_circuits::{
    evm_circuit::witness::{block_apply_mpt_state, block_convert_with_l1_queue_index, Block},
    util::SubCircuit,
    witness::WithdrawProof,
};

pub type WitnessBlock = Block<Fr>;

pub const SUB_CIRCUIT_NAMES: [&str; 14] = [
    "evm", "state", "bytecode", "copy", "keccak", "tx", "rlp", "exp", "modexp", "pi", "poseidon",
    "sig", "ecc", "mpt",
];

// TODO: optimize it later
pub fn calculate_row_usage_of_trace(
    block_trace: &BlockTrace,
) -> Result<Vec<zkevm_circuits::super_circuit::SubcircuitRowUsage>> {
    let witness_block = block_traces_to_witness_block(std::slice::from_ref(block_trace))?;
    calculate_row_usage_of_witness_block(&witness_block)
}

pub fn calculate_row_usage_of_witness_block(
    witness_block: &Block<Fr>,
) -> Result<Vec<zkevm_circuits::super_circuit::SubcircuitRowUsage>> {
    let mut rows = <super::SuperCircuit as TargetCircuit>::Inner::min_num_rows_block_subcircuits(
        witness_block,
    );

    assert_eq!(SUB_CIRCUIT_NAMES[10], "poseidon");
    assert_eq!(SUB_CIRCUIT_NAMES[13], "mpt");
    // empirical estimation is each row in mpt cost 1.5 hash (aka 12 rows)
    rows[10].row_num_real += rows[13].row_num_real * 12;

    log::debug!(
        "row usage of block {:?}, tx num {:?}, tx calldata len sum {}, rows needed {:?}",
        witness_block
            .context
            .ctxs
            .first_key_value()
            .map_or(0.into(), |(_, ctx)| ctx.number),
        witness_block.txs.len(),
        witness_block
            .txs
            .iter()
            .map(|t| t.call_data_length)
            .sum::<usize>(),
        rows,
    );
    Ok(rows)
}

// FIXME: we need better API name for this.
// This function also mutates the block trace.
pub fn check_batch_capacity(block_traces: &mut Vec<BlockTrace>) -> Result<()> {
    let block_traces_len = block_traces.len();
    let total_tx_count = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    let total_tx_len_sum = block_traces
        .iter()
        .flat_map(|b| b.transactions.iter().map(|t| t.data.len()))
        .sum::<usize>();
    log::info!(
        "check capacity of block traces, num_block {}, num_tx {}, tx total len {}",
        block_traces_len,
        total_tx_count,
        total_tx_len_sum
    );

    if block_traces_len > MAX_INNER_BLOCKS {
        bail!("too many blocks");
    }

    if !*AUTO_TRUNCATE {
        log::debug!("AUTO_TRUNCATE=false, keep batch as is");
        return Ok(());
    }

    let t = Instant::now();
    let mut acc: Vec<crate::zkevm::SubCircuitRowUsage> = Vec::new();
    let mut n_txs = 0;
    let mut truncate_idx = block_traces.len();
    for (idx, block) in block_traces.iter().enumerate() {
        let usage = calculate_row_usage_of_trace(block)?
            .into_iter()
            .map(|x| crate::zkevm::SubCircuitRowUsage {
                name: x.name,
                row_number: x.row_num_real,
            })
            .collect_vec();
        if acc.is_empty() {
            acc = usage.clone();
        } else {
            acc.iter_mut().zip(usage.iter()).for_each(|(acc, usage)| {
                acc.row_number += usage.row_number;
            });
        }
        let rows: usize = itertools::max(acc.iter().map(|x| x.row_number)).unwrap();
        log::debug!(
            "row usage after block {}({:?}): {}, {:?}",
            idx,
            block.header.number,
            rows,
            usage
        );
        n_txs += block.transactions.len();
        if rows > (1 << *INNER_DEGREE) - 256 || n_txs > MAX_TXS {
            log::warn!(
                "truncate blocks [{}..{}), n_txs {}, rows {}",
                idx,
                block_traces_len,
                n_txs,
                rows
            );
            truncate_idx = idx;
            break;
        }
    }
    log::debug!("check_batch_capacity takes {:?}", t.elapsed());
    block_traces.truncate(truncate_idx);
    let total_tx_count2 = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    if total_tx_count != 0 && total_tx_count2 == 0 {
        // the circuit cannot even prove the first non-empty block...
        bail!("circuit capacity not enough");
    }
    Ok(())
}

pub fn block_traces_to_witness_block(block_traces: &[BlockTrace]) -> Result<Block<Fr>> {
    let block_num = block_traces.len();
    let total_tx_num = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    if total_tx_num > MAX_TXS {
        bail!(
            "tx num overflow {}, block range {} to {}",
            total_tx_num,
            block_traces[0].header.number.unwrap(),
            block_traces[block_num - 1].header.number.unwrap()
        );
    }
    log::info!(
        "block_traces_to_witness_block, block num {}, tx num {}",
        block_num,
        total_tx_num,
    );
    for block_trace in block_traces {
        log::debug!("start_l1_queue_index: {}", block_trace.start_l1_queue_index,);
    }
    let old_root = if block_traces.is_empty() {
        eth_types::Hash::zero()
    } else {
        block_traces[0].storage_trace.root_before
    };
    block_traces_to_witness_block_with_updated_state(block_traces, false)
}

pub fn block_traces_to_padding_witness_block(block_traces: &[BlockTrace]) -> Result<Block<Fr>> {
    log::debug!(
        "block_traces_to_padding_witness_block, input len {:?}",
        block_traces.len()
    );
    let chain_id = block_traces
        .iter()
        .map(|block_trace| block_trace.chain_id)
        .next()
        .unwrap_or(*CHAIN_ID);
    if *CHAIN_ID != chain_id {
        bail!(
            "CHAIN_ID env var is wrong. chain id in trace {chain_id}, CHAIN_ID {}",
            *CHAIN_ID
        );
    }
    let old_root = if block_traces.is_empty() {
        eth_types::Hash::zero()
    } else {
        block_traces[0].storage_trace.root_before
    };

    // the only purpose here it to get the updated zktrie state
    let prev_witness_block =
        block_traces_to_witness_block_with_updated_state(block_traces, false)?;

    // TODO: when prev_witness_block.tx.is_empty(), the `withdraw_proof` here should be a subset of
    // storage proofs of prev block
    let storage_trace = normalize_withdraw_proof(&prev_witness_block.mpt_updates.withdraw_proof);
    storage_trace_to_padding_witness_block(storage_trace)
}

pub fn storage_trace_to_padding_witness_block(storage_trace: StorageTrace) -> Result<Block<Fr>> {
    log::debug!(
        "withdraw proof {}",
        serde_json::to_string_pretty(&storage_trace)?
    );

    let dummy_chunk_traces = vec![BlockTrace {
        chain_id: *CHAIN_ID,
        storage_trace,
        ..Default::default()
    }];

    block_traces_to_witness_block_with_updated_state(&[], false)
}

pub fn block_traces_to_witness_block_with_updated_state(
    block_traces: &[BlockTrace],
    light_mode: bool, // light_mode used in row estimation
) -> Result<Block<Fr>> {
    let chain_id = block_traces
        .iter()
        .map(|block_trace| block_trace.chain_id)
        .next()
        .unwrap_or(*CHAIN_ID);
    // total l1 msgs popped before this chunk
    let start_l1_queue_index = block_traces
        .iter()
        .map(|block_trace| block_trace.start_l1_queue_index)
        .next()
        .unwrap_or(0);
    if *CHAIN_ID != chain_id {
        bail!(
            "CHAIN_ID env var is wrong. chain id in trace {chain_id}, CHAIN_ID {}",
            *CHAIN_ID
        );
    }

    let circuit_params = CircuitsParams {
        max_evm_rows: MAX_RWS,
        max_rws: MAX_RWS,
        max_copy_rows: MAX_RWS,
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_bytecode: MAX_BYTECODE,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_keccak_rows: MAX_KECCAK_ROWS,
        max_exp_steps: MAX_EXP_STEPS,
        max_mpt_rows: MAX_MPT_ROWS,
        max_rlp_rows: MAX_CALLDATA,
        max_ec_ops: PrecompileEcParams {
            ec_add: MAX_PRECOMPILE_EC_ADD,
            ec_mul: MAX_PRECOMPILE_EC_MUL,
            ec_pairing: MAX_PRECOMPILE_EC_PAIRING,
        },
    };

    let first_trace = &block_traces[0];
    let more_traces = &block_traces[1..];

    let metric = |builder: &CircuitInputBuilder, idx: usize| -> Result<(), bus_mapping::Error>{            
        let t = Instant::now();
        let block = block_convert_with_l1_queue_index::<Fr>(
            &builder.block,
            &builder.code_db,
            builder.block.start_l1_queue_index,
        )?;
        log::debug!("block convert time {:?}", t.elapsed());
        let rows = <super::SuperCircuit as TargetCircuit>::Inner::min_num_rows_block(&block);
        log::debug!(
            "after block {}, tx num {:?}, tx len sum {}, rows needed {:?}. estimate time: {:?}",
            idx,
            builder.block.txs().len(),
            builder
                .block
                .txs()
                .iter()
                .map(|t| t.input.len())
                .sum::<usize>(),
            rows,
            t.elapsed()
        );
        Ok(())
    };

    let mut builder = CircuitInputBuilder::new_from_l2_trace(
        circuit_params,
        first_trace,
        more_traces.len() != 0,
    )?;

    let per_block_metric = false;
    if per_block_metric {
        metric(&builder, 0)?;
    }

    for (idx, block_trace) in block_traces.iter().enumerate() {
        let is_last = idx == block_traces.len() - 1;
        builder.add_more_l2_trace(block_trace, !is_last)?;
        let per_block_metric = false;
        if per_block_metric {
            metric(&builder, idx+1)?;
        }
    }

    builder.finalize_building()?;

    log::debug!("converting builder.block to witness block");
    let mut witness_block =
        block_convert_with_l1_queue_index(&builder.block, &builder.code_db, start_l1_queue_index)?;
    log::debug!(
        "witness_block built with circuits_params {:?}",
        witness_block.circuits_params
    );

    if !light_mode && builder.mpt_init_state.root() != &[0u8; 32] {
        log::debug!("block_apply_mpt_state");
        block_apply_mpt_state(&mut witness_block, &builder.mpt_init_state);
        log::debug!("block_apply_mpt_state done");
    }
    log::debug!(
        "finish replay trie updates, root {}",
        hex::encode(builder.mpt_init_state.root())
    );
    Ok(witness_block)
}

pub fn decode_bytecode(bytecode: &str) -> Result<Vec<u8>> {
    let mut stripped = if let Some(stripped) = bytecode.strip_prefix("0x") {
        stripped.to_string()
    } else {
        bytecode.to_string()
    };

    let bytecode_len = stripped.len() as u64;
    if !bytecode_len.is_even() {
        stripped = format!("0{stripped}");
    }

    hex::decode(stripped).map_err(|e| e.into())
}

pub fn normalize_withdraw_proof(proof: &WithdrawProof) -> StorageTrace {
    let address = *bus_mapping::l2_predeployed::message_queue::ADDRESS;
    let key = *bus_mapping::l2_predeployed::message_queue::WITHDRAW_TRIE_ROOT_SLOT;
    StorageTrace {
        // Not typo! We are preparing `StorageTrace` for the dummy padding chunk
        // So `post_state_root` of prev chunk will be `root_before` for new chunk
        root_before: H256::from(proof.state_root.to_be_bytes()),
        root_after: H256::from(proof.state_root.to_be_bytes()),
        proofs: Some(HashMap::from([(
            address,
            proof
                .account_proof
                .iter()
                .map(|b| b.clone().into())
                .collect(),
        )])),
        storage_proofs: HashMap::from([(
            address,
            HashMap::from([(
                key,
                proof
                    .storage_proof
                    .iter()
                    .map(|b| b.clone().into())
                    .collect(),
            )]),
        )]),
        deletion_proofs: Default::default(),
    }
}
