use super::circuit::{
    block_traces_to_witness_block_with_updated_state, calculate_row_usage_of_witness_block,
};
use itertools::Itertools;
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
        /*
        const MAX_TXS: usize = 100;
        const MAX_INNER_BLOCKS: usize = 100;
        const MAX_EXP_STEPS: usize = 10_000;
        const MAX_CALLDATA: usize = 400_000;
        const MAX_BYTECODE: usize = 400_000;
        const MAX_MPT_ROWS: usize = 400_000;
        const MAX_KECCAK_ROWS: usize = 524_000;
        const MAX_RWS: usize = 1_000_000;
        const MAX_PRECOMPILE_EC_ADD: usize = 50;
        const MAX_PRECOMPILE_EC_MUL: usize = 50;
        const MAX_PRECOMPILE_EC_PAIRING: usize = 2;
        */
        use super::circuit::{
            MAX_BYTECODE, MAX_CALLDATA, MAX_EXP_STEPS, MAX_KECCAK_ROWS, MAX_MPT_ROWS, MAX_RWS,
        };
        // 14 in total
        // "evm", "state", "bytecode", "copy",
        // "keccak", "tx", "rlp", "exp", "modexp", "pi",
        // "poseidon", "sig", "ecc", "mpt",
        let real_available_rows = [
            MAX_RWS,
            MAX_RWS,
            MAX_BYTECODE,
            MAX_RWS,
            MAX_KECCAK_ROWS,
            MAX_CALLDATA,
            MAX_CALLDATA,
            7 * MAX_EXP_STEPS, // exp
            MAX_KECCAK_ROWS,
            MAX_RWS,
            MAX_MPT_ROWS,    // poseidon
            (1 << 20) - 256, // sig
            (1 << 20) - 256, // FIXME: pairing may be limit to 1, fix later
            MAX_MPT_ROWS,
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
            light_mode: true,
        }
    }
    pub fn reset(&mut self) {
        self.acc_row_usage = RowUsage::new();
        self.row_usages = Vec::new();
    }
    pub fn estimate_circuit_capacity(
        &mut self,
        txs: &[TxTrace],
    ) -> Result<(RowUsage, RowUsage), anyhow::Error> {
        assert!(!txs.is_empty());
        let traces = txs;
        let witness_block =
            block_traces_to_witness_block_with_updated_state(traces, self.light_mode)?;
        let rows = calculate_row_usage_of_witness_block(&witness_block)?;
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
        Ok((self.acc_row_usage.normalize(), tx_row_usage.normalize()))
    }
}
