use crate::utils::read_env_var;
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use once_cell::sync::Lazy;
use rand_xorshift::XorShiftRng;
use std::collections::HashMap;

mod evm;
mod inner_circuit;
mod inner_proof;
mod mock;
mod outer_circuit;
mod outer_proof;
mod util;

pub use inner_proof::TargetCircuitProof;
pub use outer_proof::AggCircuitProof;

#[cfg(target_os = "linux")]
extern crate procfs;

pub static OPT_MEM: Lazy<bool> = Lazy::new(|| read_env_var("OPT_MEM", false));
pub static MOCK_PROVE: Lazy<bool> = Lazy::new(|| read_env_var("MOCK_PROVE", false));

#[derive(Debug)]
/// This is the aggregation prover that takes in a list of traces, produces
/// a proof that can be verified on chain.
pub struct Prover {
    pub params: ParamsKZG<Bn256>,
    pub agg_params: ParamsKZG<Bn256>,
    pub rng: XorShiftRng,
    /// We may have a list of public keys for different inner circuits.
    /// Those keys are stored as a hash map, and keyed by a `name` String.
    pub target_circuit_pks: HashMap<String, ProvingKey<G1Affine>>,
    pub agg_pk: Option<ProvingKey<G1Affine>>,
}
