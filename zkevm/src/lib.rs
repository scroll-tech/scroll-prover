pub mod circuit;
pub mod io;
pub mod prover;
pub mod utils;
pub mod verifier;

pub mod proof {
    use crate::prover::OuterCircuitProof;
    use serde_derive::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct ZkProof {
        pub id: u64,
        pub agg_proof: OuterCircuitProof,
    }
}
