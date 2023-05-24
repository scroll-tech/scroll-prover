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

// TODO(ZZ): update to the right degree
pub(crate) const LOG_DEGREE: u32 = 19;

// TODO(ZZ): update to the right size
pub(crate) const MAX_TXS: usize = 20;

#[cfg(test)]
mod tests;
