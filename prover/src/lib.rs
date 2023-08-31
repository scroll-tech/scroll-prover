pub mod aggregator;
pub mod common;
pub mod config;
pub mod consts;
mod evm_verifier;
pub mod inner;
pub mod io;
pub mod proof;
pub mod test_util;
pub mod utils;
pub mod zkevm;

pub use common::ChunkHash;
pub use consts::{
    AGG_VK_FILENAME, CHUNK_PROTOCOL_FILENAME, CHUNK_VK_FILENAME, DEPLOYMENT_CODE_FILENAME,
};
pub use evm_verifier::EvmVerifier;
pub use proof::{BatchProof, ChunkProof, EvmProof, Proof};
pub use snark_verifier_sdk::Snark;
