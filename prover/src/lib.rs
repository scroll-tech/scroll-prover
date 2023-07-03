pub mod aggregator;
pub mod config;
mod evm_verifier;
pub mod io;
pub mod proof;
pub mod test_util;
pub mod utils;
pub mod zkevm;

pub use evm_verifier::EvmVerifier;
pub use proof::Proof;

// Terminology used throughout this library.
//
// - Inner Circuit / Target Circuit / Super Circuit: they all mean the same thing.
// The first circuit. It takes inputs from block traces, and produces proofs pi_1 that are NOT
// verified on chain.
//
// - Target Circuit proof: proof for the Inner circuit.
//
// - Aggregation Circuit.
// The second circuit. It takes pi_1 from previous section, and produces proofs pi_2 that are
// verified on chain.
//
// - AggCircuitProof: proof for the aggregation circuit.
//
// - Prover: the prover that is responsible for the whole process.
// I.e., aggregation prover that takes in a list of traces, produces
// a proof that can be verified on chain

// pub mod proof {
//     use crate::zkevm::AggCircuitProof;
//     use serde_derive::{Deserialize, Serialize};

//     #[derive(Serialize, Deserialize, Debug)]
//     pub struct ZkProof {
//         pub id: u64,
//         pub agg_proof: AggCircuitProof,
//     }
// }
