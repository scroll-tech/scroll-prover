use bus_mapping::circuit_input_builder::{Block as cBlock, CircuitInputBuilder};
use bus_mapping::operation::OperationContainer;
use bus_mapping::state_db::{Account, CodeDB, StateDB};
use eth_types::{evm_types::OpcodeId, Field};
use ethers_core::types::Bytes;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::plonk::Circuit;
use is_even::IsEven;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use strum::IntoEnumIterator;
use types::eth::{AccountProofWrapper, BlockResult};
use zkevm_circuits::evm_circuit::table::FixedTableTag;
use zkevm_circuits::evm_circuit::test::TestCircuit;
use zkevm_circuits::evm_circuit::witness::{block_convert, Block, RwMap};
use zkevm_circuits::state_circuit::StateCircuitLight as StateCircuit;

use crate::utils::read_env_var;

pub static DEGREE: Lazy<usize> = Lazy::new(|| read_env_var("DEGREE", 18));

/// For keygen_vk.
pub fn create_evm_circuit() -> TestCircuit<Fr> {
    let default_block = Block::<Fr> {
        pad_to: (1 << *DEGREE) - 64,
        ..Default::default()
    };

    // hack but useful
    let tags = if *DEGREE <= 16 {
        get_fixed_table_tags_for_block(&default_block)
    } else {
        FixedTableTag::iter().collect()
    };

    TestCircuit::new(default_block, tags)
}

/// For keygen_vk.
pub fn create_state_circuit() -> StateCircuit<Fr> {
    let rw_map = RwMap::from(&OperationContainer {
        memory: vec![],
        stack: vec![],
        storage: vec![],
        ..Default::default()
    });

    StateCircuit::<Fr>::new(Fr::rand(), rw_map)
}

pub fn block_result_to_circuits<F: Field>(
    block_result: &BlockResult,
) -> Result<(Block<Fr>, impl Circuit<Fr>, impl Circuit<Fr>), anyhow::Error> {
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

    Ok((
        witness_block.clone(),
        TestCircuit::<Fr>::new(witness_block.clone(), FixedTableTag::iter().collect()),
        StateCircuit::<Fr>::new(witness_block.randomness, witness_block.rws),
    ))
}

const EMPTY_ACCOUNT_CODE: &str = "0x0";

fn decode_bytecode(bytecode: &str) -> Result<Vec<u8>, anyhow::Error> {
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

fn build_statedb_and_codedb(block: &BlockResult) -> Result<(StateDB, CodeDB), anyhow::Error> {
    let mut sdb = StateDB::new();
    let mut cdb = CodeDB::new();

    cdb.insert(decode_bytecode(EMPTY_ACCOUNT_CODE)?);

    for execution_result in &block.execution_results {
        if let Some(bytecode) = execution_result.byte_code.clone() {
            cdb.insert(decode_bytecode(&bytecode)?);
        }
    }

    for er in block.execution_results.iter().rev() {
        for step in &er.exec_steps {
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

fn trace_code(cdb: &mut CodeDB, code: Bytes) {
    cdb.insert(code.to_vec());
}

fn trace_proof(sdb: &mut StateDB, proof: Option<AccountProofWrapper>) {
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

fn get_fixed_table_tags_for_block(block: &Block<Fr>) -> Vec<FixedTableTag> {
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
