use itertools::Itertools;
use types::eth::BlockTrace;

use crate::circuit::{calculate_row_usage_of_trace, SUB_CIRCUIT_NAMES, DEGREE};

#[derive(Debug, Clone)]
pub struct RowUsage {
    pub is_ok: bool,
    pub row_number: usize,
    pub row_usage_details: Vec<(String, usize)>,
}

impl RowUsage {
    pub fn new() -> Self {
        Self {
            is_ok: true,
            row_number: 0,
            row_usage_details: Vec::new(),
        }
    }
    pub fn from_row_usage_details(row_usage_details: &Vec<(String, usize)>) -> Self {
        let row_number = *row_usage_details.iter().map(|(_name, n)| n).max().unwrap();
        Self {
            row_usage_details: row_usage_details.clone(),
            row_number,
            is_ok: row_number < 1<<*DEGREE - 256,
        }
    }
    pub fn add(&mut self, other: &RowUsage) {
        if self.row_usage_details.is_empty() {
            self.row_usage_details = other.row_usage_details.clone();
        } else {
            assert_eq!(self.row_usage_details.len(), other.row_usage_details.len());
            for i in 0..self.row_usage_details.len() {
                self.row_usage_details[i].1 += other.row_usage_details[i].1;
            }
        }

        self.row_number = *self.row_usage_details.iter().map(|(_name, n)| n).max().unwrap();
        self.is_ok = self.row_number < 1<<*DEGREE - 256;
    }
}

#[derive(Debug, Clone)]
pub struct RealtimeRowEstimator {
    pub current_row_usage: RowUsage,
}

// Currently TxTrace is same as BlockTrace, with "transactions" and "executionResults" should be of len 1,
// "storageProofs" should contain "slot touched" during when executing this tx. 
pub type TxTrace = BlockTrace;

// Used inside sequencer to estimate the row usage, so sequencer can decide when to deal a block.
impl RealtimeRowEstimator {
    pub fn new() -> Self {
        Self {
            current_row_usage: RowUsage::new(),
        }
    }
    pub fn add_tx(&mut self, tx: &BlockTrace) -> Result<(RowUsage, RowUsage), anyhow::Error> {
        let rows = calculate_row_usage_of_trace(tx)?;
        let row_usage_details: Vec<(String, usize)> = SUB_CIRCUIT_NAMES.into_iter().map(|s| s.to_string()).zip_eq(rows.into_iter()).collect_vec();
        let tx_row_usage = RowUsage::from_row_usage_details(&row_usage_details);
        self.current_row_usage.add(&tx_row_usage);
        Ok((self.current_row_usage.clone(), tx_row_usage))
    }
}