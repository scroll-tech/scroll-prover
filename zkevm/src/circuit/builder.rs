use bus_mapping::circuit_input_builder::{Block as cBlock, CircuitInputBuilder};

use bus_mapping::state_db::{Account, CodeDB, StateDB};
use eth_types::{evm_types::OpcodeId, Field};
use ethers_core::types::Bytes;

use halo2_proofs::pairing::bn256::Fr;

use is_even::IsEven;

use std::collections::HashMap;
use strum::IntoEnumIterator;
use types::eth::{AccountProofWrapper, BlockResult};
use zkevm_circuits::evm_circuit::table::FixedTableTag;

use zkevm_circuits::evm_circuit::witness::{block_convert, Block};

use super::DEGREE;

pub fn block_result_to_witness_block<F: Field>(
    block_result: &BlockResult,
) -> Result<Block<Fr>, anyhow::Error> {
    let chain_id = if let Some(tx_trace) = block_result.block_trace.transactions.get(0) {
        tx_trace.chain_id
    } else {
        0i16.into()
    };

    let eth_block = block_result.block_trace.clone().into();

    let mut geth_trace = Vec::new();
    for result in &block_result.execution_results {
        geth_trace.push(result.into());
    }

    // TODO: Get the history_hashes.
    let circuit_block = cBlock::new(chain_id, Vec::new(), &eth_block)?;
    let (state_db, code_db) = build_statedb_and_codedb(block_result)?;

    let mut builder = CircuitInputBuilder::new(state_db, code_db, circuit_block);
    builder.handle_block(&eth_block, geth_trace.as_slice())?;

    let mut witness_block = block_convert(&builder.block, &builder.code_db);
    witness_block.pad_to = (1 << *DEGREE) - 64;

    Ok(witness_block)
}

const EMPTY_ACCOUNT_CODE: &str = "0x0";

pub fn decode_bytecode(bytecode: &str) -> Result<Vec<u8>, anyhow::Error> {
    let mut stripped = if let Some(stripped) = bytecode.strip_prefix("0x") {
        stripped.to_string()
    } else {
        bytecode.to_string()
    };

    let bytecode_len = stripped.len() as u64;
    if !bytecode_len.is_even() {
        stripped = format!("0{}", stripped);
    }

    hex::decode(stripped).map_err(|e| e.into())
}

pub fn build_statedb_and_codedb(block: &BlockResult) -> Result<(StateDB, CodeDB), anyhow::Error> {
    let mut sdb = StateDB::new();
    let mut cdb = CodeDB::new();

    cdb.insert(decode_bytecode(EMPTY_ACCOUNT_CODE)?);

    for execution_result in &block.execution_results {
        if let Some(bytecode) = execution_result.byte_code.clone() {
            cdb.insert(decode_bytecode(&bytecode)?);
        }
    }

    for er in block.execution_results.iter().rev() {
        for step in er.exec_steps.iter().rev() {
            if let Some(data) = &step.extra_data {
                match step.op {
                    OpcodeId::CALL | OpcodeId::CALLCODE => {
                        let caller_code = data.get_code_at(0);
                        let callee_code = data.get_code_at(1);
                        trace_code(&mut cdb, caller_code);
                        trace_code(&mut cdb, callee_code);

                        let caller_proof = data.get_proof_at(0);
                        let last_proof = data.get_proof_at(1);
                        trace_proof(&mut sdb, caller_proof);
                        trace_proof(&mut sdb, last_proof);
                    }

                    OpcodeId::DELEGATECALL | OpcodeId::STATICCALL => {
                        let caller_code = data.get_code_at(0);
                        let callee_code = data.get_code_at(1);
                        trace_code(&mut cdb, caller_code);
                        trace_code(&mut cdb, callee_code);
                    }

                    OpcodeId::CREATE | OpcodeId::CREATE2 => {
                        let created_code = data.get_code_at(0);
                        trace_code(&mut cdb, created_code);

                        let create_proof = data.get_proof_at(0);
                        trace_proof(&mut sdb, create_proof)
                    }

                    OpcodeId::SLOAD | OpcodeId::SSTORE | OpcodeId::SELFBALANCE => {
                        let contract_proof = data.get_proof_at(0);
                        trace_proof(&mut sdb, contract_proof)
                    }

                    OpcodeId::SELFDESTRUCT => {
                        let caller_proof = data.get_proof_at(0);
                        let callee_proof = data.get_proof_at(1);
                        trace_proof(&mut sdb, caller_proof);
                        trace_proof(&mut sdb, callee_proof);
                    }

                    OpcodeId::EXTCODEHASH | OpcodeId::BALANCE => {
                        let proof = data.get_proof_at(0);
                        trace_proof(&mut sdb, proof)
                    }

                    OpcodeId::CODESIZE
                    | OpcodeId::CODECOPY
                    | OpcodeId::EXTCODESIZE
                    | OpcodeId::EXTCODECOPY => {
                        let code = data.get_code_at(0);
                        trace_code(&mut cdb, code)
                    }

                    _ => {}
                }
            }
        }

        trace_proof(&mut sdb, er.to.clone());
        trace_proof(&mut sdb, er.from.clone());
    }

    trace_proof(&mut sdb, Some(block.block_trace.coinbase.clone()));

    Ok((sdb, cdb))
}

pub fn trace_code(cdb: &mut CodeDB, code: Bytes) {
    cdb.insert(code.to_vec());
}

pub fn trace_proof(sdb: &mut StateDB, proof: Option<AccountProofWrapper>) {
    // `to` may be empty
    if proof.is_none() {
        return;
    }
    let proof = proof.unwrap();

    let (found, acc) = sdb.get_account(&proof.address.unwrap());
    let mut storage = match found {
        true => acc.storage.clone(),
        false => HashMap::new(),
    };

    if let Some(s) = &proof.storage {
        log::trace!(
            "trace_proof ({:?}, {:?}) => {:?}",
            &proof.address.unwrap(),
            s.key.unwrap(),
            s.value.unwrap()
        );
        storage.insert(s.key.unwrap(), s.value.unwrap());
    }

    sdb.set_account(
        &proof.address.unwrap(),
        Account {
            nonce: proof.nonce.unwrap().into(),
            balance: proof.balance.unwrap(),
            storage,
            code_hash: proof.code_hash.unwrap(),
        },
    )
}

pub fn get_fixed_table_tags_for_block(block: &Block<Fr>) -> Vec<FixedTableTag> {
    let need_bitwise_lookup = block.txs.iter().any(|tx| {
        tx.steps.iter().any(|step| {
            matches!(
                step.opcode,
                Some(OpcodeId::AND) | Some(OpcodeId::OR) | Some(OpcodeId::XOR)
            )
        })
    });

    FixedTableTag::iter()
        .filter(|t| {
            !matches!(
                t,
                FixedTableTag::BitwiseAnd | FixedTableTag::BitwiseOr | FixedTableTag::BitwiseXor
            ) || need_bitwise_lookup
        })
        .collect()
}
