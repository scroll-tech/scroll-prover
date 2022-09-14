use std::collections::HashMap;
use ethers_core::abi::Address;
use zktrie::ZkMemoryDb;
use types::eth::{AccountProofWrapper, BlockResult};
use super::mpt::AccountProof;


pub struct WitnessGenerator<'a> {
    db: ZkMemoryDb,
}

impl WitnessGenerator {
    pub fn new(block: &BlockResult) -> Self {
        let db = ZkMemoryDb::new();
        let storage_trace = &block.storage_trace;

        let accounts: HashMap<Address, AccountProof> = storage_trace.proofs
            .iter()
            .flatten()
            .map(|(account, proofs)| (*account, proofs.as_slice().try_into().unwrap()))
            .collect();

        // for (account, storage_map) in storage_trace.storage_proofs.iter() {
        //     for (k, v_proofs) in storage_map {
        //
        //     }
        // }



        Self {
            db,
        }
    }
}