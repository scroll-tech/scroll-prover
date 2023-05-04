use anyhow::Result;
use serde_derive::{Deserialize, Serialize};
use snark_verifier_sdk::Snark;
use std::fs::File;
use std::path::Path;
use types::base64;

#[derive(Debug, Deserialize, Serialize)]
pub struct TargetCircuitProof {
    pub name: String,
    pub snark: Snark,
    #[serde(with = "base64", default)]
    pub vk: Vec<u8>,
    pub num_of_proved_blocks: usize,
    pub total_num_of_blocks: usize,
}

impl TargetCircuitProof {
    pub fn dump_to_file(&self, file_path: &str) -> Result<()> {
        let mut fd = File::create(file_path)?;
        serde_json::to_writer_pretty(&mut fd, self)?;

        Ok(())
    }

    /// Return the proof if file exists, otherwise return None.
    pub fn restore_from_file(file_path: &str) -> Result<Option<Self>> {
        if !Path::new(file_path).exists() {
            return Ok(None);
        }

        let fd = File::open(file_path)?;
        Ok(Some(serde_json::from_reader(fd)?))
    }
}
