pub mod aggregator;
pub mod common;
pub mod config;
mod evm_verifier;
pub mod inner;
pub mod io;
pub mod proof;
pub mod test_util;
pub mod utils;
pub mod zkevm;

pub use common::ChunkHash;
pub use evm_verifier::EvmVerifier;
pub use proof::{BatchProof, ChunkProof, EvmProof, Proof};
pub use snark_verifier_sdk::Snark;
