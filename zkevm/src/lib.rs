pub mod capacity_checker;
pub mod circuit;
pub mod io;
pub mod prover;
pub mod utils;
pub mod verifier;

pub mod test_util;

// Terminology used throughout this library.
//
// - Inner Circuit / Target Circuit / Super Circuit: they all mean the same thing.
// The first circuit. It takes inputs from block traces, and produces proofs pi_1 that are NOT verified on chain.
//
// - Target Circuit proof: proof for the Inner circuit.
//
// - Aggregation Circuit.
// The second circuit. It takes pi_1 from previous section, and produces proofs pi_2 that are verified on chain.
//
// - AggCircuitProof: proof for the aggregation circuit.
//
// - Prover: the prover that is responsible for the whole process.
// I.e., aggregation prover that takes in a list of traces, produces
// a proof that can be verified on chain

pub mod proof {
    use crate::prover::AggCircuitProof;
    use serde_derive::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct ZkProof {
        pub id: u64,
        pub agg_proof: AggCircuitProof,
    }
}
