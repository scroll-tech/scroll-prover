use crate::io::{
    deserialize_fr_matrix, deserialize_vk, serialize_fr_matrix, serialize_vk, write_file,
};
use anyhow::{bail, Result};
use halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::{Circuit, ProvingKey, VerifyingKey},
};
use serde_derive::{Deserialize, Serialize};
use snark_verifier::Protocol;
use snark_verifier_sdk::Snark;
use std::{
    fs::File,
    path::{Path, PathBuf},
};
use types::{base64, eth::StorageTrace};

#[derive(Debug, Deserialize, Serialize)]
pub struct ChunkProof {
    storage_trace: StorageTrace,
    protocol: Protocol<G1Affine>,
    #[serde(with = "base64")]
    proof: Vec<u8>,
    #[serde(with = "base64")]
    instances: Vec<u8>,
    #[serde(with = "base64")]
    vk: Vec<u8>,
}

impl ChunkProof {
    pub fn new(
        snark: Snark,
        storage_trace: StorageTrace,
        pk: Option<&ProvingKey<G1Affine>>,
    ) -> Result<Self> {
        let instances = serde_json::to_vec(&serialize_fr_matrix(&snark.instances))?;
        let vk = pk.map_or_else(Vec::new, |pk| serialize_vk(pk.get_vk()));

        Ok(Self {
            storage_trace,
            protocol: snark.protocol,
            proof: snark.proof,
            instances,
            vk,
        })
    }

    pub fn from_file(name: &str, dir: &str) -> Result<Self> {
        let file_path = Self::dump_proof_path(name, dir);
        if !Path::new(&file_path).exists() {
            bail!("File {file_path} doesn't exist");
        }

        let fd = File::open(file_path)?;
        let mut deserializer = serde_json::Deserializer::from_reader(fd);
        deserializer.disable_recursion_limit();
        let deserializer = serde_stacker::Deserializer::new(&mut deserializer);

        Ok(serde::Deserialize::deserialize(deserializer)?)
    }

    pub fn dump(&self, name: &str, dir: &str) -> Result<()> {
        // Write vk as bytes.
        write_file(
            &mut PathBuf::from(dir),
            &format!("chunk_vk_{name}.vkey"),
            &self.vk,
        );

        // Write full proof as json.
        let mut fd = File::create(Self::dump_proof_path(name, dir))?;
        serde_json::to_writer_pretty(&mut fd, &self)?;

        Ok(())
    }

    pub fn to_snark_and_storage_trace(self) -> (Snark, StorageTrace) {
        let instances = self.instances();

        (
            Snark {
                protocol: self.protocol,
                proof: self.proof,
                instances,
            },
            self.storage_trace,
        )
    }

    pub fn vk<C: Circuit<Fr>>(&self) -> VerifyingKey<G1Affine> {
        deserialize_vk::<C>(&self.vk)
    }

    fn dump_proof_path(name: &str, dir: &str) -> String {
        format!("{dir}/chunk_proof_{name}.json")
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        let buf: Vec<Vec<Vec<_>>> = serde_json::from_reader(self.instances.as_slice()).unwrap();

        deserialize_fr_matrix(buf)
    }
}
