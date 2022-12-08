use bus_mapping::circuit_input_builder::{BlockHead, CircuitInputBuilder, CircuitsParams};

use bus_mapping::state_db::{Account, CodeDB, StateDB};
use eth_types::evm_types::OpcodeId;
use eth_types::{ToAddress, Word};
use ethers_core::types::{Address, Bytes, U256};

use halo2_proofs::halo2curves::bn256::Fr;

use is_even::IsEven;

use super::{mpt, MAX_CALLDATA, MAX_RWS, MAX_TXS};
use std::collections::HashMap;
use types::eth::{BlockTrace, EthBlock, ExecStep};

use halo2_proofs::arithmetic::FieldExt;
use mpt_circuits::hash::Hashable;
use zkevm_circuits::evm_circuit::witness::{block_convert, Block, Bytecode};

use anyhow::anyhow;

pub fn verify_proof_leaf<T: Default>(
    inp: mpt::TrieProof<T>,
    key_buf: &[u8; 32],
) -> mpt::TrieProof<T> {
    let first_16bytes: [u8; 16] = key_buf[..16].try_into().expect("expect first 16 bytes");
    let last_16bytes: [u8; 16] = key_buf[16..].try_into().expect("expect last 16 bytes");

    let bt_high = Fr::from_u128(u128::from_be_bytes(first_16bytes));
    let bt_low = Fr::from_u128(u128::from_be_bytes(last_16bytes));

    if let Some(key) = inp.key {
        let rev_key_bytes: Vec<u8> = key.to_fixed_bytes().into_iter().rev().collect();
        let key_fr = Fr::from_bytes(&rev_key_bytes.try_into().unwrap()).unwrap();

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

pub fn block_trace_to_witness_block(block_trace: &BlockTrace) -> Result<Block<Fr>, anyhow::Error> {
    block_traces_to_witness_block(std::slice::from_ref(block_trace))
}

pub fn block_traces_to_witness_block(
    block_traces: &[BlockTrace],
) -> Result<Block<Fr>, anyhow::Error> {
    let chain_id = if let Some(tx_trace) = block_traces
        .get(0)
        .cloned()
        .unwrap_or_default()
        .transactions
        .get(0)
    {
        tx_trace.chain_id
    } else {
        0i16.into()
    };

    let (state_db, code_db) = build_statedb_and_codedb(block_traces)?;
    let circuit_params = CircuitsParams {
        max_rws: MAX_RWS,
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_bytecode: MAX_CALLDATA,
        keccak_padding: Some(80000),
    };
    let mut builder = CircuitInputBuilder::new_from_headers(
        circuit_params,
        state_db,
        code_db,
        Default::default(),
    );
    for (idx, block_trace) in block_traces.iter().enumerate() {
        let is_last = idx == block_traces.len() - 1;
        let eth_block: EthBlock = block_trace.clone().into();

        let mut geth_trace = Vec::new();
        for result in &block_trace.execution_results {
            geth_trace.push(result.into());
        }
        // TODO: Get the history_hashes.
        let mut header = BlockHead::new(chain_id, Vec::new(), &eth_block)?;
        // TODO: a temporary hacking for "miner" field in header, which do not respect coinbase
        header.coinbase = block_trace
            .coinbase
            .address
            .expect("should include coinbase address");
        builder.block.headers.insert(header.number.as_u64(), header);
        builder.handle_block_inner(&eth_block, geth_trace.as_slice(), false, is_last)?;
    }
    builder.set_value_ops_call_context_rwc_eor();
    builder.set_end_block();

    let mut witness_block = block_convert(&builder.block, &builder.code_db)?;
    witness_block.evm_circuit_pad_to = MAX_RWS;
    log::debug!(
        "witness_block.circuits_params {:?}",
        witness_block.circuits_params
    );

    // hack bytecodes table in witness
    witness_block.bytecodes = builder
        .block
        .txs()
        .iter()
        .flat_map(|tx| {
            tx.calls()
                .iter()
                .map(|call| call.code_hash)
                .into_iter()
                .map(|code_hash| {
                    let bytes = builder
                        .code_db
                        .0
                        .get(&code_hash)
                        .cloned()
                        .expect("code db should has contain the code");

                    let hash: Word = U256::from_big_endian(code_hash.as_bytes());
                    (hash, Bytecode { hash, bytes })
                })
        })
        .collect();

    Ok(witness_block)
}

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

/*
fn get_account_deployed_codehash(
    execution_result: &ExecutionResult,
) -> Result<eth_types::H256, anyhow::Error> {
    let created_acc = execution_result
        .account_created
        .as_ref()
        .expect("called when field existed")
        .address
        .as_ref()
        .unwrap();
    for state in &execution_result.account_after {
        if Some(created_acc) == state.address.as_ref() {
            return state.code_hash.ok_or_else(|| anyhow!("empty code hash"));
        }
    }
    Err(anyhow!("can not find created address in account after"))
}
fn get_account_created_codehash(step: &ExecStep) -> Result<eth_types::H256, anyhow::Error> {
    let extra_data = step
        .extra_data
        .as_ref()
        .ok_or_else(|| anyhow!("no extra data in create context"))?;
    let proof_list = extra_data
        .proof_list
        .as_ref()
        .expect("should has proof list");
    if proof_list.len() < 2 {
        Err(anyhow!("wrong fields in create context"))
    } else {
        proof_list[1]
            .code_hash
            .ok_or_else(|| anyhow!("empty code hash in final state"))
    }
}
*/
fn trace_code(
    cdb: &mut CodeDB,
    step: &ExecStep,
    sdb: &StateDB,
    code: Bytes,
    stack_pos: usize,
) -> Result<(), anyhow::Error> {
    let stack = step
        .stack
        .as_ref()
        .expect("should have stack in call context");
    let addr = stack[stack.len() - stack_pos - 1].to_address(); //stack N-stack_pos

    let (existed, data) = sdb.get_account(&addr);
    if !existed {
        // we may call non-contract or non-exist address
        if code.as_ref().is_empty() {
            Ok(())
        } else {
            Err(anyhow!("missed account data for {}", addr))
        }
    } else {
        cdb.0.insert(data.code_hash, code.to_vec());
        Ok(())
    }
}
pub fn build_statedb_and_codedb(blocks: &[BlockTrace]) -> Result<(StateDB, CodeDB), anyhow::Error> {
    let mut sdb = StateDB::new();
    let mut cdb = CodeDB::new();

    // step1: insert proof into statedb
    for block in blocks.iter().rev() {
        let storage_trace = &block.storage_trace;
        if let Some(acc_proofs) = &storage_trace.proofs {
            for (addr, acc) in acc_proofs.iter() {
                let acc_proof: mpt::AccountProof = acc.as_slice().try_into()?;
                let acc = verify_proof_leaf(acc_proof, &mpt::extend_address_to_h256(addr));
                if acc.key.is_some() {
                    // a valid leaf
                    let (_, acc_mut) = sdb.get_account_mut(addr);
                    acc_mut.nonce = acc.data.nonce.into();
                    acc_mut.code_hash = acc.data.code_hash;
                    acc_mut.balance = acc.data.balance;
                } else {
                    // TODO(@noel2004): please complete the comment below.
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
                }
            }
        }

        for (addr, s_map) in storage_trace.storage_proofs.iter() {
            let (found, acc) = sdb.get_account_mut(addr);
            if !found {
                log::error!("missed address in proof field show in storage: {:?}", addr);
                continue;
            }

            for (k, val) in s_map {
                let mut k_buf: [u8; 32] = [0; 32];
                k.to_big_endian(&mut k_buf[..]);
                let val_proof: mpt::StorageProof = val.as_slice().try_into()?;
                let val = verify_proof_leaf(val_proof, &k_buf);

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

        // step2: insert code into codedb
        // notice empty codehash always kept as keccak256(nil)
        cdb.insert(Vec::new());

        for execution_result in &block.execution_results {
            if let Some(bytecode) = &execution_result.byte_code {
                if execution_result.account_created.is_none() {
                    cdb.0.insert(
                        execution_result
                            .code_hash
                            .ok_or_else(|| anyhow!("empty code hash in result"))?,
                        decode_bytecode(bytecode)?.to_vec(),
                    );
                }
            }

            for step in execution_result.exec_steps.iter().rev() {
                if let Some(data) = &step.extra_data {
                    match step.op {
                        OpcodeId::CALL
                        | OpcodeId::CALLCODE
                        | OpcodeId::DELEGATECALL
                        | OpcodeId::STATICCALL => {
                            let callee_code = data.get_code_at(1);
                            trace_code(&mut cdb, step, &sdb, callee_code, 1)?;
                        }
                        OpcodeId::CREATE | OpcodeId::CREATE2 => {
                            // TODO: need to insert code to codedb with poseidon codehash
                            // if the call is persistent
                        }
                        OpcodeId::EXTCODESIZE | OpcodeId::EXTCODECOPY => {
                            let code = data.get_code_at(0);
                            trace_code(&mut cdb, step, &sdb, code, 0).unwrap_or_else(|err| {
                                log::error!("temporarily skip error in EXTCODE op: {}", err);
                            });
                        }

                        _ => {}
                    }
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
