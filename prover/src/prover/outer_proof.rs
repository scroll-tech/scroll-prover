use crate::io::{
    write_verify_circuit_instance, write_verify_circuit_proof, write_verify_circuit_vk,
};
use anyhow::Result;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use types::base64;

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
    pub fn dump(&self, dir: &mut PathBuf) -> Result<()> {
        write_verify_circuit_instance(dir, &self.instance);
        write_verify_circuit_proof(dir, &self.proof);
        write_verify_circuit_vk(dir, &self.vk);

        dir.push("full_proof.data");
        let mut fd = std::fs::File::create(dir.as_path())?;
        dir.pop();
        serde_json::to_writer_pretty(&mut fd, &self)?;

        Ok(())
    }
}
