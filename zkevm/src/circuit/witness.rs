use std::collections::HashMap;
use eth_types::Hash;
use ethers_core::abi::Address;
use zktrie::{ZkMemoryDb, ZkTrie};
use types::eth::BlockResult;
use crate::circuit::builder::{extend_address_to_h256, verify_proof_leaf};
use crate::circuit::mpt::StorageProof;
use super::mpt::AccountProof;


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

        let accounts: HashMap<Address, AccountProof> = storage_trace.proofs
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
}