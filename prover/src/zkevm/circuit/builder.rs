use super::{
    TargetCircuit, AUTO_TRUNCATE, CHAIN_ID, MAX_BYTECODE, MAX_CALLDATA, MAX_EXP_STEPS,
    MAX_INNER_BLOCKS, MAX_KECCAK_ROWS, MAX_MPT_ROWS, MAX_RWS, MAX_TXS,
};
use crate::config::INNER_DEGREE;
use anyhow::{bail, Result};
use bus_mapping::{
    circuit_input_builder::{self, BlockHead, CircuitInputBuilder, CircuitsParams},
    state_db::{Account, CodeDB, StateDB},
};
use eth_types::{evm_types::opcode_ids::OpcodeId, ToAddress, H256};
use ethers_core::types::{Bytes, U256};
use halo2_proofs::halo2curves::bn256::Fr;
use is_even::IsEven;
use itertools::Itertools;
use mpt_zktrie::state::ZktrieState;
use std::{collections::hash_map::Entry, time::Instant};
use types::eth::{BlockTrace, EthBlock, ExecStep};
use zkevm_circuits::{
    evm_circuit::witness::{block_apply_mpt_state, block_convert, Block},
    util::SubCircuit,
};

pub const SUB_CIRCUIT_NAMES: [&str; 11] = [
    "evm", "state", "bytecode", "copy", "keccak", "tx", "rlp", "exp", "pi", "poseidon", "mpt",
];

// TODO: optimize it later
pub fn calculate_row_usage_of_trace(block_trace: &BlockTrace) -> Result<Vec<usize>> {
    let witness_block = block_traces_to_witness_block(std::slice::from_ref(block_trace), true)?;
    calculate_row_usage_of_witness_block(&witness_block)
}

pub fn calculate_row_usage_of_witness_block(witness_block: &Block<Fr>) -> Result<Vec<usize>> {
    let rows = <super::SuperCircuit as TargetCircuit>::Inner::min_num_rows_block_subcircuits(
        witness_block,
    )
    .0;

    log::debug!(
        "row usage of block {:?}, tx num {:?}, tx len sum {}, rows needed {:?}",
        witness_block.context.first_or_default().number,
        witness_block.txs.len(),
        witness_block
            .txs
            .iter()
            .map(|t| t.call_data_length)
            .sum::<usize>(),
        SUB_CIRCUIT_NAMES.iter().zip_eq(rows.iter())
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
    let mut acc = Vec::new();
    let mut truncate_idx = block_traces.len();
    for (idx, block) in block_traces.iter().enumerate() {
        let usage = calculate_row_usage_of_trace(block)?;
        if acc.is_empty() {
            acc = usage;
        } else {
            acc.iter_mut().zip(usage.iter()).for_each(|(acc, usage)| {
                *acc += usage;
            });
        }
        let rows = itertools::max(&acc).unwrap();
        let rows_and_names: Vec<(_, _)> = SUB_CIRCUIT_NAMES
            .iter()
            .zip_eq(acc.iter())
            .collect::<Vec<(_, _)>>();
        log::debug!(
            "row usage after block {}({:?}): {}, {:?}",
            idx,
            block.header.number,
            rows,
            rows_and_names
        );
        if *rows >= (1 << *INNER_DEGREE) - 256 {
            log::warn!("truncate blocks [{}..{})", idx, block_traces_len);
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

pub fn update_state(
    zktrie_state: &mut ZktrieState,
    block_traces: &[BlockTrace],
    light_mode: bool,
) -> Result<()> {
    log::debug!("building partial statedb");
    let account_proofs = block_traces.iter().rev().flat_map(|block| {
        log::trace!("account proof for block {:?}:", block.header.number);
        block.storage_trace.proofs.iter().flat_map(|kv_map| {
            kv_map
                .iter()
                .map(|(k, bts)| (k, bts.iter().map(Bytes::as_ref)))
        })
    });
    let storage_proofs = block_traces.iter().rev().flat_map(|block| {
        log::trace!("storage proof for block {:?}:", block.header.number);
        block
            .storage_trace
            .storage_proofs
            .iter()
            .flat_map(|(k, kv_map)| {
                kv_map
                    .iter()
                    .map(move |(sk, bts)| (k, sk, bts.iter().map(Bytes::as_ref)))
            })
    });
    let additional_proofs = block_traces.iter().rev().flat_map(|block| {
        log::trace!("storage proof for block {:?}:", block.header.number);
        log::trace!("additional proof for block {:?}:", block.header.number);
        block
            .storage_trace
            .deletion_proofs
            .iter()
            .map(Bytes::as_ref)
    });
    zktrie_state.update_statedb_from_proofs(
        account_proofs.clone(),
        storage_proofs.clone(),
        additional_proofs.clone(),
    )?;
    if !light_mode {
        zktrie_state.update_nodes_from_proofs(account_proofs, storage_proofs, additional_proofs)?;
    }
    log::debug!("building partial statedb done");
    Ok(())
}

pub fn block_traces_to_witness_block(block_traces: &[BlockTrace], light_mode: bool) -> Result<Block<Fr>> {
    log::debug!(
        "block_traces_to_witness_block, input len {:?}",
        block_traces.len()
    );
    let old_root = if block_traces.is_empty() {
        eth_types::Hash::zero()
    } else {
        block_traces[0].storage_trace.root_before
    };
    let mut state = ZktrieState::construct(old_root);
    update_state(&mut state, block_traces, light_mode)?;
    block_traces_to_witness_block_with_updated_state(block_traces, &mut state, light_mode)
}

pub fn block_traces_to_witness_block_with_updated_state(
    block_traces: &[BlockTrace],
    zktrie_state: &mut ZktrieState,
    light_mode: bool, // light_mode used in row estimation
) -> Result<Block<Fr>> {
    let chain_ids = block_traces
        .iter()
        .map(|block_trace| block_trace.chain_id)
        .collect::<Vec<_>>();

    let chain_id = if !chain_ids.is_empty() {
        chain_ids[0]
    } else {
        *CHAIN_ID
    };

    let mut state_db: StateDB = zktrie_state.state().clone();

    let (zero_coinbase_exist, _) = state_db.get_account(&Default::default());
    if !zero_coinbase_exist {
        state_db.set_account(&Default::default(), Account::zero());
    }

    let code_db = build_codedb(&state_db, block_traces)?;
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
    };
    let mut builder_block = circuit_input_builder::Block::from_headers(&[], circuit_params);
    builder_block.chain_id = chain_id;
    builder_block.prev_state_root = U256::from(zktrie_state.root());
    let mut builder = CircuitInputBuilder::new(state_db.clone(), code_db, &builder_block);
    for (idx, block_trace) in block_traces.iter().enumerate() {
        let is_last = idx == block_traces.len() - 1;
        let eth_block: EthBlock = block_trace.clone().into();

        let mut geth_trace = Vec::new();
        for result in &block_trace.execution_results {
            geth_trace.push(result.into());
        }
        // TODO: Get the history_hashes.
        let mut header = BlockHead::new(chain_id, Vec::new(), &eth_block)?;
        // override zeroed minder field with additional "coinbase" field in blocktrace
        if let Some(address) = block_trace.coinbase.address {
            header.coinbase = address;
        }
        let block_num = header.number.as_u64();
        builder.block.headers.insert(block_num, header);
        builder.handle_block_inner(&eth_block, geth_trace.as_slice(), false, is_last)?;
        log::debug!("handle_block_inner done for block {:?}", block_num);
        let per_block_metric = false;
        if per_block_metric {
            let t = Instant::now();
            let block = block_convert::<Fr>(&builder.block, &builder.code_db)?;
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
        }
    }

    builder.set_value_ops_call_context_rwc_eor();
    builder.set_end_block()?;

    log::debug!("converting builder.block to witness block");
    let mut witness_block = block_convert(&builder.block, &builder.code_db)?;
    log::debug!(
        "witness_block built with circuits_params {:?}",
        witness_block.circuits_params
    );

    if !light_mode && !block_traces.is_empty() {
        log::debug!("block_apply_mpt_state");
        block_apply_mpt_state(&mut witness_block, zktrie_state);
        log::debug!("block_apply_mpt_state done");
    }
    zktrie_state.set_state(builder.sdb.clone());
    log::debug!("finish replay trie updates");
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

fn trace_code(
    cdb: &mut CodeDB,
    code_hash: Option<H256>,
    code: Bytes,
    step: &ExecStep,
    sdb: &StateDB,
    stack_pos: usize,
) {
    // first, try to read from sdb
    let stack = step
        .stack
        .as_ref()
        .expect("should have stack in call context");
    let addr = stack[stack.len() - stack_pos - 1].to_address(); //stack N-stack_pos

    let code_hash = code_hash.or_else(|| {
        let (_existed, acc_data) = sdb.get_account(&addr);
        if acc_data.code_hash != CodeDB::empty_code_hash() && !code.is_empty() {
            // they must be same
            Some(acc_data.code_hash)
        } else {
            // let us re-calculate it
            None
        }
    });
    let code_hash = match code_hash {
        Some(code_hash) => {
            if log::log_enabled!(log::Level::Trace) {
                assert_eq!(
                    code_hash,
                    CodeDB::hash(&code),
                    "bytecode len {:?}, step {:?}",
                    code.len(),
                    step
                );
            }
            code_hash
        }
        None => CodeDB::hash(&code),
    };

    let code = code.to_vec();

    log::debug!(
        "trace code addr {:?}, size {} hash {:?}",
        addr,
        code.len(),
        code_hash
    );
    cdb.0.insert(code_hash, code);
    log::debug!("trace code addr {:?} done", addr);
}
pub fn build_codedb(sdb: &StateDB, blocks: &[BlockTrace]) -> Result<CodeDB> {
    let mut cdb = CodeDB::new();
    log::debug!("building codedb");

    cdb.insert(Vec::new());

    for block in blocks.iter().rev() {
        for (er_idx, execution_result) in block.execution_results.iter().enumerate() {
            if let Some(bytecode) = &execution_result.byte_code {
                let bytecode = decode_bytecode(bytecode)?.to_vec();
                let code_hash = execution_result
                    .to
                    .as_ref()
                    .and_then(|t| t.poseidon_code_hash)
                    .unwrap_or_else(|| CodeDB::hash(&bytecode));
                if let Entry::Vacant(e) = cdb.0.entry(code_hash) {
                    e.insert(bytecode);
                    //log::debug!("inserted tx bytecode {:?} {:?}", code_hash, hash);
                }
                if execution_result.account_created.is_none() {
                    //assert_eq!(Some(hash), execution_result.code_hash);
                }
            }

            for step in execution_result.exec_steps.iter().rev() {
                if let Some(data) = &step.extra_data {
                    match step.op {
                        OpcodeId::CALL
                        | OpcodeId::CALLCODE
                        | OpcodeId::DELEGATECALL
                        | OpcodeId::STATICCALL => {
                            let code_idx = if block.transactions[er_idx].to.is_none() {
                                0
                            } else {
                                1
                            };
                            let callee_code = data.get_code_at(code_idx);
                            if callee_code.is_none() {
                                bail!("invalid trace: cannot get code of call: {:?}", step);
                            }
                            let code_hash = match step.op {
                                OpcodeId::CALL | OpcodeId::CALLCODE => data.get_code_hash_at(1),
                                OpcodeId::STATICCALL => data.get_code_hash_at(0),
                                _ => None,
                            };
                            trace_code(&mut cdb, code_hash, callee_code.unwrap(), step, sdb, 1);
                        }
                        OpcodeId::CREATE | OpcodeId::CREATE2 => {
                            // notice we do not need to insert code for CREATE,
                            // bustmapping do this job
                        }
                        OpcodeId::EXTCODESIZE | OpcodeId::EXTCODECOPY => {
                            let code = data.get_code_at(0);
                            if code.is_none() {
                                bail!("invalid trace: cannot get code of ext: {:?}", step);
                            }
                            trace_code(&mut cdb, None, code.unwrap(), step, sdb, 0);
                        }

                        _ => {}
                    }
                }
            }
        }
    }

    log::debug!("building codedb done");
    Ok(cdb)
}
