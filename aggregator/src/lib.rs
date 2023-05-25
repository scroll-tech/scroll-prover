//! This module implements circuits that aggregates public inputs of many blocks/txs into a single
//! one.

// This module implements `Chunk` related data types.
// A chunk is a list of blocks.
mod chunk;
// This module implements `Batch` related data types.
// A batch is a list of chunk.
mod batch;
// Circuit implementation of `BatchHash`.
mod circuit;
// SubCircuit implementation of `BatchHash`.
mod sub_circuit;
// Circuit and SubCircuit configurations
mod config;
/// utilities
mod util;

pub use batch::BatchHash;
pub use chunk::ChunkHash;
pub use circuit::{BatchHashCircuit, BatchHashCircuitPublicInput};
pub use config::{BatchCircuitConfig, BatchCircuitConfigArgs};

// TODO(ZZ): update to the right degree
pub(crate) const LOG_DEGREE: u32 = 19;

// Each round requires (NUM_ROUNDS+1) * DEFAULT_KECCAK_ROWS = 300 rows.
// This library is hard coded for this parameter.
// Modifying the following parameters may result into bugs.
// Adopted from keccak circuit
pub(crate) const DEFAULT_KECCAK_ROWS: usize = 12;
// Adopted from keccak circuit
pub(crate) const NUM_ROUNDS: usize = 24;

#[cfg(test)]
mod tests;
