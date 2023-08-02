use super::{dump_as_json, dump_vk, from_json_file, serialize_instance, Proof};
use crate::io::serialize_fr_vec;
use anyhow::Result;
use serde_derive::{Deserialize, Serialize};

const ACC_LEN: usize = 12;
const PI_LEN: usize = 32;

const ACC_BYTES: usize = ACC_LEN * 32;

#[derive(Debug, Deserialize, Serialize)]
pub struct BatchProof {
    #[serde(flatten)]
    raw: Proof,
}

impl From<Proof> for BatchProof {
    fn from(proof: Proof) -> Self {
        let instances = proof.instances();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].len(), ACC_LEN + PI_LEN);

        let vk = proof.vk;
        let proof = proof
            .proof
            .into_iter()
            .chain(
                serialize_fr_vec(&instances[0][..ACC_LEN])
                    .into_iter()
                    .flatten(),
            )
            .collect();

        let instances = serialize_instance(&instances[0][ACC_LEN..]);

        Self {
            raw: Proof {
                proof,
                instances,
                vk,
            },
        }
    }
}

impl BatchProof {
    pub fn from_json_file(dir: &str, name: &str) -> Result<Self> {
        from_json_file(dir, &dump_filename(name))
    }

    pub fn dump(&self, dir: &str, name: &str) -> Result<()> {
        let filename = dump_filename(name);

        dump_vk(dir, &filename, &self.raw.vk);
        dump_as_json(dir, &filename, &self)
    }

    pub fn proof_to_verify(self) -> Proof {
        assert!(self.raw.proof.len() > ACC_BYTES);
        assert_eq!(self.raw.instances.len(), PI_LEN);

        let proof_len = self.raw.proof.len() - ACC_BYTES;

        let mut proof = self.raw.proof;
        let mut instances = proof.split_off(proof_len);
        instances.extend(self.raw.instances);

        let vk = self.raw.vk;

        Proof {
            proof,
            instances,
            vk,
        }
    }
}

fn dump_filename(name: &str) -> String {
    format!("chunk_{name}")
}
