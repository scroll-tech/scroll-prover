use super::mpt::AccountProof;
use crate::circuit::builder::verify_proof_leaf;
use crate::circuit::mpt::{extend_address_to_h256, StorageProof};
use eth_types::{Hash, H256, U256};
use ethers_core::abi::Address;
use mpt_circuits::hash::Hashable;
use mpt_circuits::serde::{HexBytes, SMTNode, SMTPath, SMTTrace, StateData};
use std::collections::HashMap;
use types::eth::{AccountProofWrapper, BlockResult};
use halo2_proofs::pairing::bn256::Fr;
// todo: in new halo2 lib we import halo2_proofs::halo2curves::group::ff::{Field, PrimeField};
use halo2_proofs::pairing::group::ff::{Field, PrimeField};
use halo2_proofs::arithmetic::{BaseExt, FieldExt};
use zktrie::{ZkMemoryDb, ZkTrie};

use num_bigint::BigUint;
use std::io::{Error as IoError, Read};

pub struct WitnessGenerator {
    db: ZkMemoryDb,
    trie: ZkTrie,
    accounts: HashMap<Address, AccountProof>,
    storages: HashMap<Address, ZkTrie>,
}

impl WitnessGenerator {
    pub fn new(block: &BlockResult) -> Self {
        let mut db = ZkMemoryDb::new();
        let storage_trace = &block.storage_trace;

        let accounts: HashMap<Address, AccountProof> = storage_trace
            .proofs
            .iter()
            .flatten()
            .map(|(account, proofs)| {
                let proof = proofs.as_slice().try_into().unwrap();
                let proof = verify_proof_leaf(proof, &extend_address_to_h256(account));
                (*account, proof)
            })
            .collect();

        let mut storages = HashMap::new();
        for (account, storage_map) in storage_trace.storage_proofs.iter() {
            assert!(accounts.contains_key(account));
            if accounts[account].key.is_none() {
                storages.insert(*account, db.new_trie(&Hash::zero().0).unwrap());
            }
            for (k, v_proofs) in storage_map {
                let mut k_buf: [u8; 32] = [0; 32];
                k.to_big_endian(&mut k_buf[..]);
                let proof: StorageProof = v_proofs.as_slice().try_into().unwrap();
                let _ = verify_proof_leaf(proof, &k_buf);
                storages.insert(*account, db.new_trie(&k_buf).unwrap());
            }
        }

        let trie = db.new_trie(&storage_trace.root_before.0).unwrap();

        Self {
            db,
            trie,
            accounts,
            storages,
        }
    }

    fn trace_storage_update(
        &mut self,
        address: Address,
        key: &[u8; 32],
        value: &[u8; 32],
    ) -> SMTTrace {
        let storage_key = hash_zktrie_key(key);
        let key = HexBytes(*key);
        let store_value = HexBytes(*value);
        let trie = self.storages.get_mut(&address).unwrap();

        let store_before = trie
            .get_store(key.as_ref())
            .and_then(|v| if &v == &Hash::zero().0 { None } else { Some(v) })
            .map(|v| StateData {
                key,
                value: HexBytes(v),
            });
        let storage_before_proofs = trie.prove(key.as_ref());
        let storage_before_path = decode_proof_for_mpt_path(storage_key, storage_before_proofs);
        let store_after = if value != &Hash::zero().0 {
            Some(StateData {
                key,
                value: store_value,
            })
        } else {
            trie.delete(key.as_ref());
            None
        };
        let storage_after_proofs = trie.prove(key.as_ref());
        let storage_after_path = decode_proof_for_mpt_path(storage_key, storage_after_proofs);

        let mut out = self.trace_account_update(address, |acc_data| {
            let mut acc = acc_data.data;
            acc.storage_root = H256::from(storage_after_path.as_ref().unwrap().root.as_ref());
            AccountProof {
                data: acc,
                key: acc_data.key
            }
        });
        if store_before.is_some() {
            out.state_key = Some(
                storage_before_path
                    .as_ref()
                    .unwrap()
                    .leaf
                    .as_ref()
                    .unwrap()
                    .sibling,
            );
        } else if store_after.is_some() {
            out.state_key = Some(
                storage_after_path
                    .as_ref()
                    .unwrap()
                    .leaf
                    .as_ref()
                    .unwrap()
                    .sibling,
            );
        } else {
            let high = Fr::from_u128(u128::from_be_bytes((&key.0[..16]).try_into().unwrap()));
            let low = Fr::from_u128(u128::from_be_bytes((&key.0[16..]).try_into().unwrap()));
            let hash = Fr::hash([high, low]);
            let mut buf = [0u8; 32];
            hash.write(&mut buf.as_mut_slice()).unwrap();
            out.state_key = Some(HexBytes(buf));
        }

        out.state_path = [storage_before_path.ok(), storage_after_path.ok()];
        out.state_update = Some([store_before, store_after]);
        out
    }

    fn trace_account_update<U>(&mut self, address: Address, update_account_data: U) -> SMTTrace
    where
        U: FnOnce(&AccountProof) -> AccountProof,
    {
        let account_data_before = self
            .accounts
            .get(&address)
            .expect("todo: handle this");

        let proofs = self.trie.prove(address.as_bytes());
        let address_key = hash_zktrie_key(&extend_address_to_h256(&address));

        let account_path_before = decode_proof_for_mpt_path(address_key, proofs).unwrap();
        // TODO: verify account for sanity check
        let (account_key, account_update_before) = if account_data_before.key.is_some() {
            (Some(account_path_before.leaf.clone().unwrap().sibling), Some(account_data_before.data.into()))
        } else {
            (None, None)
        };

        let account_data_after = update_account_data(account_data_before);
        let account_update_after = if account_data_after.key.is_some() {
            Some(account_data_after.data.into())
        } else {
            None
        };

        if account_data_after.key.is_some() {
            let mut nonce = [0u8; 32];
            U256::from(account_data_after.data.nonce).to_big_endian(&mut nonce.as_mut_slice());
            let mut balance = [0u8; 32];
            U256::from(account_data_after.data.balance).to_big_endian(&mut balance.as_mut_slice());
            let mut code_hash = [0u8; 32];
            U256::from(account_data_after.data.code_hash.0).to_big_endian(&mut code_hash.as_mut_slice());
            let acc_data = [nonce, balance, code_hash, [0; 32]];
            self.trie.update_account(address.as_bytes(), &acc_data).expect("todo: handle this");
            self.accounts.insert(address, account_data_after);
        } else {
            self.trie.delete(address.as_bytes());
            self.accounts.remove(&address);
        }

        let proofs = self.trie.prove(address.as_bytes());
        let account_path_after = decode_proof_for_mpt_path(address_key, proofs).unwrap();


        SMTTrace {
            address: HexBytes(address.0),
            account_path: [account_path_before.clone(), account_path_after.clone()],
            account_update: [account_update_before, account_update_after.clone()],
            account_key: account_key.unwrap_or(account_path_after.leaf.unwrap().sibling),
            state_path: [None, None],
            common_state_root: None,
            state_key: None,
            state_update: None,
        }
    }

    fn handle_new_state(&self, account_proof: &AccountProofWrapper) {}
}

fn smt_path_from_middle_node(node_data: &[u8], key_bit_one: bool) -> Result<SMTNode, IoError> {

    // we need little-endian represent for output hashes while we have big-endian bytes
    // so we use a trick to read middle node from end
    let rev_node_data : Vec<_> = node_data.iter().rev().copied().collect();

    let mut rd = rev_node_data.as_slice();
    let mut out = SMTNode{
        value: HexBytes([0;32]),
        sibling: HexBytes([0;32]),
    };

    // notice we read right child first from reversed bytes
    if key_bit_one {
        rd.read_exact(out.value.0.as_mut_slice())?;
        rd.read_exact(out.sibling.0.as_mut_slice())?;
    } else {
        rd.read_exact(out.sibling.0.as_mut_slice())?;
        rd.read_exact(out.value.0.as_mut_slice())?;        
    }

    Ok(out)

}

fn hash_zktrie_key(key_buf: &[u8; 32]) -> Fr {

    let first_16bytes: [u8; 16] = key_buf[..16].try_into().expect("expect first 16 bytes");
    let last_16bytes: [u8; 16] = key_buf[16..].try_into().expect("expect last 16 bytes");

    let bt_high = Fr::from_u128(u128::from_be_bytes(first_16bytes));
    let bt_low = Fr::from_u128(u128::from_be_bytes(last_16bytes));

    Fr::hash([bt_high, bt_low])
}

fn decode_proof_for_mpt_path(mut key_fr: Fr, proofs: Vec<Vec<u8>>) -> Result<SMTPath, IoError> {

    let invert_2 = Fr::one().double().invert().unwrap();
    let mut out = SMTPath{
        root: HexBytes::<32>([0; 32]),
        leaf: None,
        path: Vec::new(),
        path_part: Default::default(),
    };
    let mut path_bit_now = BigUint::from(1 as u32);

    for proof_bytes in proofs {
        let is_bit_one : bool = key_fr.is_odd().into();
        out.path.push(smt_path_from_middle_node(&proof_bytes, is_bit_one)?);
        key_fr = if is_bit_one {key_fr.mul(&invert_2) - invert_2 } else {key_fr.mul(&invert_2)};
        if is_bit_one {out.path_part += &path_bit_now};
        path_bit_now *= 2 as u32;
    }

    Ok(out)
}
