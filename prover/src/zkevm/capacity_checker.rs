use super::circuit::{
    block_traces_to_witness_block_with_updated_state, calculate_row_usage_of_witness_block,
    update_state, SUB_CIRCUIT_NAMES,
};
use crate::config::INNER_DEGREE;
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

impl RowUsage {
    pub fn new() -> Self {
        Self {
            is_ok: true,
            row_number: 0,
            row_usage_details: Vec::new(),
        }
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
            is_ok: row_number < (1 << *INNER_DEGREE) - 256,
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
        self.is_ok = self.row_number < (1 << *INNER_DEGREE) - 256;
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
    ) -> Result<(RowUsage, RowUsage), anyhow::Error> {
        assert!(!txs.is_empty());
        if self.state.is_none() {
            self.state = Some(ZktrieState::construct(txs[0].storage_trace.root_before));
        }
        let traces = txs;
        let state = self.state.as_mut().unwrap();
        update_state(state, traces, self.light_mode)?;
        let witness_block =
            block_traces_to_witness_block_with_updated_state(traces, state, self.light_mode)?;
        let rows = calculate_row_usage_of_witness_block(&witness_block)?;
        let row_usage_details: Vec<SubCircuitRowUsage> = SUB_CIRCUIT_NAMES
            .into_iter()
            .map(|s| s.to_string())
            .zip_eq(rows.into_iter())
            .map(|(name, row_number)| SubCircuitRowUsage { name, row_number })
            .collect_vec();
        let tx_row_usage = RowUsage::from_row_usage_details(row_usage_details);
        self.row_usages.push(tx_row_usage.clone());
        self.acc_row_usage.add(&tx_row_usage);
        Ok((self.acc_row_usage.clone(), tx_row_usage))
    }
}
