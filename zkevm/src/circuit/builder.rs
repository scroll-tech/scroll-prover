use bus_mapping::circuit_input_builder::{Block as cBlock, CircuitInputBuilder};

use bus_mapping::state_db::{Account, CodeDB, StateDB};
use eth_types::{evm_types::OpcodeId, Field};
use ethers_core::types::{Address, Bytes};

use halo2_proofs::pairing::bn256::Fr;

use is_even::IsEven;

use std::collections::HashMap;
use strum::IntoEnumIterator;
use types::eth::BlockResult;
use types::mpt;
use zkevm_circuits::evm_circuit::table::FixedTableTag;

use halo2_proofs::arithmetic::{BaseExt, FieldExt};
use mpt_circuits::hash::Hashable;
use zkevm_circuits::evm_circuit::witness::{block_convert, Block};

use super::DEGREE;

fn verify_proof_leaf<T: Default>(inp: mpt::TrieProof<T>, key_buf: &[u8; 32]) -> mpt::TrieProof<T> {
    let first_16bytes: [u8; 16] = key_buf[..16].try_into().expect("expect first 16 bytes");
    let last_16bytes: [u8; 16] = key_buf[16..].try_into().expect("expect last 16 bytes");

    let bt_high = Fr::from_u128(u128::from_be_bytes(first_16bytes));
    let bt_low = Fr::from_u128(u128::from_be_bytes(last_16bytes));

    if let Some(key) = inp.key {
        let rev_key_bytes: Vec<u8> = key.to_fixed_bytes().into_iter().rev().collect();
        let key_fr = Fr::read(&mut rev_key_bytes.as_slice()).unwrap();

        let secure_hash = Fr::hash([bt_high, bt_low]);

        if key_fr == secure_hash {
            inp
        } else {
            Default::default()
        }
    } else {
        inp
    }
}

fn extend_address_to_h256(src: &Address) -> [u8; 32] {
    let mut bts: Vec<u8> = src.as_bytes().into();
    bts.resize(32, 0);
    bts.as_slice().try_into().expect("32 bytes")
}

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
    witness_block.evm_circuit_pad_to = (1 << *DEGREE) - 64;

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

    cdb.insert(None, decode_bytecode(EMPTY_ACCOUNT_CODE)?);

    for execution_result in &block.execution_results {
        if let Some(bytecode) = execution_result.byte_code.clone() {
            cdb.insert(None, decode_bytecode(&bytecode)?);
        }
    }

    let storage_trace = &block.storage_trace;
    if let Some(acc_proofs) = &storage_trace.proofs {
        for (addr, acc) in acc_proofs.as_ref() {
            let acc = verify_proof_leaf(acc.clone(), &extend_address_to_h256(addr));
            if acc.key.is_some() {
                // a valid leaf
                sdb.set_account(
                    addr,
                    Account {
                        nonce: acc.data.nonce.into(),
                        balance: acc.data.balance,
                        storage: HashMap::new(),
                        code_hash: acc.data.code_hash,
                    },
                );
            //                log::info!("set account {:?}, {:?}", addr, acc.data);
            } else {
                // only
                sdb.set_account(
                    addr,
                    Account {
                        nonce: Default::default(),
                        balance: Default::default(),
                        storage: HashMap::new(),
                        code_hash: Default::default(),
                    },
                );
                //                log::info!("set empty account {:?}", addr);
            }
        }
    }

    for (addr, s_map) in storage_trace.storage_proofs.as_ref() {
        let (found, acc) = sdb.get_account_mut(addr);
        if !found {
            log::error!("missed address in proof field show in storage: {:?}", addr);
            continue;
        }

        for (k, val) in s_map {
            let mut k_buf: [u8; 32] = [0; 32];
            k.to_big_endian(&mut k_buf[..]);

            let val = verify_proof_leaf(val.clone(), &k_buf);

            if val.key.is_some() {
                // a valid leaf
                acc.storage.insert(*k, *val.data.as_ref());
            //                log::info!("set storage {:?} {:?} {:?}", addr, k, val.data);
            } else {
                // add 0
                acc.storage.insert(*k, Default::default());
                //                log::info!("set empty storage {:?} {:?}", addr, k);
            }
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
                    }
                    /*
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
                    */
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
    }

    // A temporary fix: zkgeth do not trace 0 address if it is only refered as coinbase
    // (For it is not the "real" coinbase address in PoA) but would still refer it for
    // other reasons (like being transferred or called), in the other way, busmapping
    // seems always refer it as coinbase (?)
    // here we just add it as unexisted account and consider fix it in zkgeth later (always
    // record 0 addr inside storageTrace field)
    let (zero_coinbase_exist, _) = sdb.get_account(&Default::default());
    if !zero_coinbase_exist {
        sdb.set_account(
            &Default::default(),
            Account {
                nonce: Default::default(),
                balance: Default::default(),
                storage: HashMap::new(),
                code_hash: Default::default(),
            },
        );
    }

    Ok((sdb, cdb))
}

pub fn trace_code(cdb: &mut CodeDB, code: Bytes) {
    cdb.insert(None, code.to_vec());
}
/*
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
*/
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
