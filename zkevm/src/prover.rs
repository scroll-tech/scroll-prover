use crate::io::{
    write_verify_circuit_instance, write_verify_circuit_proof, write_verify_circuit_vk,
};
use crate::utils::read_env_var;
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use once_cell::sync::Lazy;
use rand_xorshift::XorShiftRng;
use serde_derive::{Deserialize, Serialize};
use snark_verifier_sdk::Snark;
use std::collections::HashMap;
use std::path::PathBuf;
use types::base64;

mod evm;
mod inner_circuit;
mod mock;
mod outer_circuit;
mod util;

#[cfg(target_os = "linux")]
extern crate procfs;

pub static OPT_MEM: Lazy<bool> = Lazy::new(|| read_env_var("OPT_MEM", false));
pub static MOCK_PROVE: Lazy<bool> = Lazy::new(|| read_env_var("MOCK_PROVE", false));

#[derive(Deserialize, Serialize, Debug)]
pub struct TargetCircuitProof {
    pub name: String,
    pub snark: Snark,
    #[serde(with = "base64", default)]
    pub vk: Vec<u8>,
    pub num_of_proved_blocks: usize,
    pub total_num_of_blocks: usize,
}

#[derive(Deserialize, Serialize, Debug, Default)]
pub struct AggCircuitProof {
    #[serde(with = "base64")]
    pub proof: Vec<u8>,
    #[serde(with = "base64")]
    pub instance: Vec<u8>,
    #[serde(with = "base64")]
    pub vk: Vec<u8>,
    pub total_proved_block_count: usize,
}

impl AggCircuitProof {
    pub fn write_to_dir(&self, out_dir: &mut PathBuf) {
        write_verify_circuit_instance(out_dir, &self.instance);
        write_verify_circuit_proof(out_dir, &self.proof);
        write_verify_circuit_vk(out_dir, &self.vk);

        out_dir.push("full_proof.data");
        let mut fd = std::fs::File::create(out_dir.as_path()).unwrap();
        out_dir.pop();
        serde_json::to_writer_pretty(&mut fd, &self).unwrap()
    }
}

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
    pub debug_dir: String,
}
