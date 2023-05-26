//! This module implements circuits that aggregates public inputs and proofs of many chunks into a single
//! one.
//!

// This module implements `Chunk` related data types.
// A chunk is a list of blocks.
mod chunk;
// This module implements `Batch` related data types.
// A batch is a list of chunk.
mod batch;
// Public input aggregation.
// see `public_input_aggregation.rs` for the spec.
mod public_input_aggregation;
/// utilities
mod util;

pub use batch::BatchHash;
pub use chunk::ChunkHash;
pub use public_input_aggregation::{BatchCircuitConfig, BatchCircuitConfigArgs};
pub use public_input_aggregation::{BatchHashCircuit, BatchHashCircuitPublicInput};

// Each round requires (NUM_ROUNDS+1) * DEFAULT_KECCAK_ROWS = 300 rows.
// This library is hard coded for this parameter.
// Modifying the following parameters may result into bugs.
// Adopted from keccak circuit
pub(crate) const DEFAULT_KECCAK_ROWS: usize = 12;
// Adopted from keccak circuit
pub(crate) const NUM_ROUNDS: usize = 24;
