use super::{dump_as_json, dump_vk, from_json_file, Proof};
use anyhow::Result;
use halo2_proofs::{halo2curves::bn256::G1Affine, plonk::ProvingKey};
use serde_derive::{Deserialize, Serialize};
use snark_verifier::Protocol;
use snark_verifier_sdk::Snark;
use types::eth::StorageTrace;

#[derive(Debug, Deserialize, Serialize)]
pub struct ChunkProof {
    pub storage_trace: StorageTrace,
    pub protocol: Protocol<G1Affine>,
    pub proof: Proof,
}

impl ChunkProof {
    pub fn new(
        snark: Snark,
        storage_trace: StorageTrace,
        pk: Option<&ProvingKey<G1Affine>>,
    ) -> Result<Self> {
        let protocol = snark.protocol;
        let proof = Proof::new(snark.proof, &snark.instances, pk)?;

        Ok(Self {
            storage_trace,
            protocol,
            proof,
        })
    }

    pub fn from_json_file(dir: &str, name: &str) -> Result<Self> {
        from_json_file(dir, &dump_filename(name))
    }

    pub fn dump(&self, dir: &str, name: &str) -> Result<()> {
        let filename = dump_filename(name);

        dump_vk(dir, &filename, &self.proof.vk);
        dump_as_json(dir, &filename, &self)
    }

    pub fn to_snark_and_storage_trace(self) -> (Snark, StorageTrace) {
        let instances = self.proof.instances();

        (
            Snark {
                protocol: self.protocol,
                proof: self.proof.proof,
                instances,
            },
            self.storage_trace,
        )
    }
}

fn dump_filename(name: &str) -> String {
    format!("chunk_{name}")
}
