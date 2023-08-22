use std::collections::HashMap;

use super::circuit::{
    MAX_BYTECODE, MAX_CALLDATA, MAX_EXP_STEPS, MAX_KECCAK_ROWS, MAX_MPT_ROWS, MAX_POSEIDON_ROWS,
    MAX_RWS, MAX_VERTICLE_ROWS,
};

use super::circuit::{
    block_traces_to_witness_block_with_updated_state, calculate_row_usage_of_witness_block,
    fill_zktrie_state_from_proofs,
};
use eth_types::H256;
use itertools::Itertools;
use mpt_zktrie::state::ZktrieState;
use serde_derive::{Deserialize, Serialize};
use types::eth::BlockTrace;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubCircuitRowUsage {
    pub name: String,
    pub row_number: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RowUsage {
    pub is_ok: bool,
    pub row_number: usize,
    pub row_usage_details: Vec<SubCircuitRowUsage>,
}

impl Default for RowUsage {
    fn default() -> Self {
        Self::new()
    }
}

const NORMALIZED_ROW_LIMIT: usize = 1_000_000;

impl RowUsage {
    pub fn new() -> Self {
        Self {
            is_ok: true,
            row_number: 0,
            row_usage_details: Vec::new(),
        }
    }
    // We treat 1M as 100%
    pub fn normalize(&self) -> Self {
        let real_available_rows = [
            MAX_RWS,           // evm
            MAX_RWS,           // state
            MAX_BYTECODE,      // bytecode
            MAX_RWS,           // copy
            MAX_KECCAK_ROWS,   // keccak
            MAX_CALLDATA,      // tx
            MAX_CALLDATA,      // rlp
            7 * MAX_EXP_STEPS, // exp
            MAX_KECCAK_ROWS,   // modexp
            MAX_RWS,           // pi
            MAX_POSEIDON_ROWS, // poseidon
            MAX_VERTICLE_ROWS, // sig
            MAX_VERTICLE_ROWS, // ecc
            MAX_MPT_ROWS,      // mpt
        ]
        .map(|x| (x as f32 * 0.95) as usize);
        let details = self
            .row_usage_details
            .iter()
            .zip_eq(real_available_rows.iter())
            .map(|(x, limit)| SubCircuitRowUsage {
                name: x.name.clone(),
                row_number: (1_000_000u64 * (x.row_number as u64) / (*limit as u64)) as usize,
            })
            .collect_vec();
        log::debug!(
            "normalize row usage, before {:#?}\nafter {:#?}",
            self.row_usage_details,
            details
        );
        Self::from_row_usage_details(details)
    }
    pub fn from_row_usage_details(row_usage_details: Vec<SubCircuitRowUsage>) -> Self {
        let row_number = row_usage_details
            .iter()
            .map(|x| x.row_number)
            .max()
            .unwrap();
        Self {
            row_usage_details,
            row_number,
            is_ok: row_number < NORMALIZED_ROW_LIMIT,
        }
    }
    pub fn add(&mut self, other: &RowUsage) {
        if self.row_usage_details.is_empty() {
            self.row_usage_details = other.row_usage_details.clone();
        } else {
            assert_eq!(self.row_usage_details.len(), other.row_usage_details.len());
            for i in 0..self.row_usage_details.len() {
                self.row_usage_details[i].row_number += other.row_usage_details[i].row_number;
            }
        }

        self.row_number = self
            .row_usage_details
            .iter()
            .map(|x| x.row_number)
            .max()
            .unwrap();
        self.is_ok = self.row_number < NORMALIZED_ROW_LIMIT;
    }
}

#[derive(Debug, Clone)]
pub struct CircuitCapacityChecker {
    /// When "light_mode" enabled, we skip zktrie subcircuit in row estimation to avoid the heavy
    /// poseidon cost.
    pub light_mode: bool,
    pub acc_row_usage: RowUsage,
    pub row_usages: Vec<RowUsage>,
    pub state: Option<ZktrieState>,
    // poseidon codehash to code len
    pub codelen: HashMap<H256, usize>,
}

// Currently TxTrace is same as BlockTrace, with "transactions" and "executionResults" should be of
// len 1, "storageProofs" should contain "slot touched" during when executing this tx.
pub type TxTrace = BlockTrace;

impl Default for CircuitCapacityChecker {
    fn default() -> Self {
        Self::new()
    }
}

// Used inside sequencer to estimate the row usage, so sequencer can decide when to deal a block.
impl CircuitCapacityChecker {
    pub fn new() -> Self {
        Self {
            acc_row_usage: RowUsage::new(),
            row_usages: Vec::new(),
            state: None,
            light_mode: true,
            codelen: HashMap::new(),
        }
    }
    pub fn reset(&mut self) {
        self.state = None;
        self.acc_row_usage = RowUsage::new();
        self.row_usages = Vec::new();
    }
    pub fn estimate_circuit_capacity(
        &mut self,
        txs: &[TxTrace],
    ) -> Result<RowUsage, anyhow::Error> {
        assert!(!txs.is_empty());
        if self.state.is_none() {
            self.state = Some(ZktrieState::construct(txs[0].storage_trace.root_before));
        }
        let traces = txs;
        let state = self.state.as_mut().unwrap();
        fill_zktrie_state_from_proofs(state, traces, self.light_mode)?;
        let (witness_block, codedb) =
            block_traces_to_witness_block_with_updated_state(traces, state, self.light_mode)?;
        let mut rows = calculate_row_usage_of_witness_block(&witness_block)?;

        // adjustment. we do dedup for bytecodes for bytecode circuit / poseidon circuit here only.
        for (hash, bytes) in &codedb.0 {
            if self.codelen.contains_key(hash) {
                assert_eq!(rows[2].name, "bytecode");
                rows[2].row_num_real -= bytes.len();
                assert_eq!(rows[10].name, "poseidon");
                rows[10].row_num_real -= bytes.len() / (31 * 2);
            } else {
                self.codelen.insert(*hash, bytes.len());
            }
        }

        let row_usage_details: Vec<SubCircuitRowUsage> = rows
            .into_iter()
            .map(|x| SubCircuitRowUsage {
                name: x.name,
                row_number: x.row_num_real,
            })
            .collect_vec();
        let tx_row_usage = RowUsage::from_row_usage_details(row_usage_details);
        self.row_usages.push(tx_row_usage.clone());
        self.acc_row_usage.add(&tx_row_usage);
        Ok(self.acc_row_usage.normalize())
    }
}
