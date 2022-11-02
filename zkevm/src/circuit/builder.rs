use bus_mapping::circuit_input_builder::{BlockHead, CircuitInputBuilder};

use bus_mapping::state_db::{Account, CodeDB, CodeHash, StateDB};
use eth_types::evm_types::OpcodeId;
use eth_types::{Hash, ToAddress};
use ethers_core::types::{Address, Bytes, U256};

use halo2_proofs::halo2curves::bn256::Fr;

use is_even::IsEven;

use super::mpt;
use std::collections::HashMap;
use strum::IntoEnumIterator;
use types::eth::{BlockResult, ExecStep};
use zkevm_circuits::evm_circuit::table::FixedTableTag;

use halo2_proofs::arithmetic::FieldExt;
use mpt_circuits::hash::{Hashable, MessageHashable};
use zkevm_circuits::evm_circuit::witness::{block_convert, Block};
use zkevm_circuits::tx_circuit::PrimeField;

use super::DEGREE;
use anyhow::anyhow;

fn verify_proof_leaf<T: Default>(inp: mpt::TrieProof<T>, key_buf: &[u8; 32]) -> mpt::TrieProof<T> {
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

fn extend_address_to_h256(src: &Address) -> [u8; 32] {
    let mut bts: Vec<u8> = src.as_bytes().into();
    bts.resize(32, 0);
    bts.as_slice().try_into().expect("32 bytes")
}

pub fn block_result_to_witness_block(
    block_result: &BlockResult,
) -> Result<Block<Fr>, anyhow::Error> {
    block_results_to_witness_block(std::slice::from_ref(block_result))
}

pub fn block_results_to_witness_block(
    block_results: &[BlockResult],
) -> Result<Block<Fr>, anyhow::Error> {
    let chain_id = if let Some(tx_trace) = block_results[0].block_trace.transactions.get(0) {
        tx_trace.chain_id
    } else {
        0i16.into()
    };

    let (state_db, code_db) = build_statedb_and_codedb(block_results)?;

    let mut builder = CircuitInputBuilder::new(state_db, code_db, Default::default());
    for (idx, block_result) in block_results.iter().enumerate() {
        let is_last = idx == block_results.len() - 1;
        let eth_block = block_result.block_trace.clone().into();
        let mut geth_trace = Vec::new();
        for result in &block_result.execution_results {
            geth_trace.push(result.into());
        }
        // TODO: Get the history_hashes.
        let header = BlockHead::new(chain_id, Vec::new(), &eth_block)?;
        builder.block.headers.insert(header.number.as_u64(), header);
        builder.handle_block_inner(&eth_block, geth_trace.as_slice(), is_last, is_last)?;
    }

    let mut witness_block = block_convert(&builder.block, &builder.code_db);
    witness_block.evm_circuit_pad_to = (1 << *DEGREE) - 64;
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

const POSEIDONHASH_BYTES_IN_FIELD: usize = 16;

#[derive(Debug, Clone)]
struct PoseidonCodeHash {
    bytes_in_field: usize,
}

impl PoseidonCodeHash {
    fn new(bytes_in_field: usize) -> Self {
        Self { bytes_in_field }
    }
}

impl CodeHash for PoseidonCodeHash {
    fn hash_code(&self, code: &[u8]) -> Hash {
        let fls = (0..(code.len() / self.bytes_in_field))
            .map(|i| i * self.bytes_in_field)
            .map(|i| {
                let mut buf: [u8; 32] = [0; 32];
                U256::from_big_endian(&code[i..i + self.bytes_in_field]).to_little_endian(&mut buf);
                Fr::from_bytes(&buf).unwrap()
            });
        let msgs: Vec<_> = fls
            .chain(if code.len() % self.bytes_in_field == 0 {
                None
            } else {
                let last_code = &code[code.len() - code.len() % self.bytes_in_field..];
                // pad to bytes_in_field
                let mut last_buf = vec![0u8; self.bytes_in_field];
                last_buf.as_mut_slice()[..last_code.len()].copy_from_slice(last_code);
                let mut buf: [u8; 32] = [0; 32];
                U256::from_big_endian(&last_buf).to_little_endian(&mut buf);
                Some(Fr::from_bytes(&buf).unwrap())
            })
            .collect();

        let h = Fr::hash_msg(&msgs, Some(code.len() as u64));

        let mut buf: [u8; 32] = [0; 32];
        U256::from_little_endian(h.to_repr().as_ref()).to_big_endian(&mut buf);
        Hash::from_slice(&buf)
    }
}

#[test]
fn code_hashing() {
    let code_hasher = PoseidonCodeHash::new(16);
    let simple_byte: [u8; 1] = [0];
    assert_eq!(
        format!("{:?}", code_hasher.hash_code(&simple_byte)),
        "0x0ee069e6aa796ef0e46cbd51d10468393d443a00f5affe72898d9ab62e335e16"
    );

    let simple_byte: [u8; 2] = [0, 1];
    assert_eq!(
        format!("{:?}", code_hasher.hash_code(&simple_byte)),
        "0x26cd650aa0d0b9aada79f5f7c03c5961430c12a2142832789fc31a4188d762ff"
    );

    let example = "608060405234801561001057600080fd5b506004361061004c5760003560e01c806321848c46146100515780632e64cec11461006d578063b0f2b72a1461008b578063f3417673146100a7575b600080fd5b61006b60048036038101906100669190610116565b6100c5565b005b6100756100da565b604051610082919061014e565b60405180910390f35b6100a560048036038101906100a09190610116565b6100e3565b005b6100af6100ed565b6040516100bc919061014e565b60405180910390f35b8060008190555060006100d757600080fd5b50565b60008054905090565b8060008190555050565b6000806100f957600080fd5b600054905090565b60008135905061011081610173565b92915050565b60006020828403121561012857600080fd5b600061013684828501610101565b91505092915050565b61014881610169565b82525050565b6000602082019050610163600083018461013f565b92915050565b6000819050919050565b61017c81610169565b811461018757600080fd5b5056fea2646970667358221220f4bca934426c76c7cb87cc32876fc6e65d1d7de23424faa61c347ffed95c449064736f6c63430008040033";
    let bytes = hex::decode(example).unwrap();

    assert_eq!(
        format!("{:?}", code_hasher.hash_code(&bytes)),
        "0x0e6d089fa72b508b90e014b486d64a5311df3030c45b10a95366cf53cd1ec9d5"
    );
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
fn trace_code(cdb: &mut CodeDB, step: &ExecStep, sdb: &StateDB, code: Bytes, stack_pos: usize) {
    let stack = step
        .stack
        .as_ref()
        .expect("should have stack in call context");
    let addr = stack[stack.len() - stack_pos - 1].to_address(); //stack N-stack_pos

    let hash = cdb.insert(code.to_vec());

    // sanity check
    let (existed, data) = sdb.get_account(&addr);
    if existed {
        assert_eq!(hash, data.code_hash);
    };
}
pub fn build_statedb_and_codedb(
    blocks: &[BlockResult],
) -> Result<(StateDB, CodeDB), anyhow::Error> {
    let mut sdb = StateDB::new();
    let mut cdb =
        CodeDB::new_with_code_hasher(Box::new(PoseidonCodeHash::new(POSEIDONHASH_BYTES_IN_FIELD)));

    // step1: insert proof into statedb
    for block in blocks.iter().rev() {
        let storage_trace = &block.storage_trace;
        if let Some(acc_proofs) = &storage_trace.proofs {
            for (addr, acc) in acc_proofs.iter() {
                let acc_proof: mpt::AccountProof = acc.as_slice().try_into()?;
                let acc = verify_proof_leaf(acc_proof, &extend_address_to_h256(addr));
                if acc.key.is_some() {
                    // a valid leaf
                    let (_, acc_mut) = sdb.get_account_mut(addr);
                    acc_mut.nonce = acc.data.nonce.into();
                    acc_mut.code_hash = acc.data.code_hash;
                    acc_mut.balance = acc.data.balance;
                } else {
                    // it is essential to set it as default (i.e. not existed account data)
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
                            trace_code(&mut cdb, step, &sdb, callee_code, 1);
                        }
                        OpcodeId::CREATE | OpcodeId::CREATE2 => {
                            // notice we do not need to insert code for CREATE,
                            // bustmapping do this job
                        }
                        OpcodeId::EXTCODESIZE | OpcodeId::EXTCODECOPY => {
                            let code = data.get_code_at(0);
                            trace_code(&mut cdb, step, &sdb, code, 0);
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
