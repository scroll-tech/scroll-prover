use crate::io::{deserialize_fr_matrix, serialize_fr_matrix, serialize_vk, write_file};
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::ProvingKey,
};
use serde_derive::{Deserialize, Serialize};
use snark_verifier::{
    util::{
        arithmetic::Domain,
        protocol::{Expression, QuotientPolynomial},
    },
    Protocol,
};
use snark_verifier_sdk::Snark;
use std::{
    fs::File,
    path::{Path, PathBuf},
};
use types::base64;

#[derive(Deserialize, Serialize, Debug, Default)]
pub struct Proof {
    #[serde(with = "base64")]
    pub proof: Vec<u8>,
    #[serde(with = "base64")]
    pub instance: Vec<u8>,
    #[serde(with = "base64")]
    pub vk: Vec<u8>,
}

impl Proof {
    pub fn from_snark(pk: &ProvingKey<G1Affine>, snark: &Snark) -> anyhow::Result<Self> {
        // Serialize instances
        let instances = serialize_fr_matrix(snark.instances.as_slice());
        let instance_bytes = serde_json::to_vec(&instances)?;

        // Serialize vk
        let vk_bytes = serialize_vk(pk.get_vk());

        Ok(Proof {
            proof: snark.proof.clone(),
            instance: instance_bytes,
            vk: vk_bytes,
        })
    }

    pub fn to_snark(&self) -> Snark {
        let instances = self.deserialize_instance();
        Snark {
            protocol: dummy_protocol(),
            instances,
            proof: self.proof.clone(),
        }
    }

    pub fn deserialize_instance(&self) -> Vec<Vec<Fr>> {
        let l3_buf: Vec<Vec<Vec<u8>>> = serde_json::from_reader(self.instance.as_slice()).unwrap();
        deserialize_fr_matrix(l3_buf)
    }

    pub fn dump(&self, dir: &mut PathBuf, name: &str) -> Result<()> {
        write_file(dir, &format!("{name}_instance.data"), &self.instance);
        write_file(dir, &format!("{name}_proof.data"), &self.proof);
        write_file(dir, &format!("{name}.vkey"), &self.proof);

        dir.push("{}_full_proof.json");
        let mut fd = std::fs::File::create(dir.as_path())?;
        dir.pop();
        serde_json::to_writer_pretty(&mut fd, &self)?;

        Ok(())
    }

    pub fn load_from_json(file_path: &str) -> Result<Option<Self>> {
        if !Path::new(file_path).exists() {
            return Ok(None);
        }

        let fd = File::open(file_path)?;
        let mut deserializer = serde_json::Deserializer::from_reader(fd);
        deserializer.disable_recursion_limit();
        let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
        let proof = serde::Deserialize::deserialize(deserializer)?;
        Ok(Some(proof))
    }
}

fn dummy_protocol() -> Protocol<G1Affine> {
    Protocol {
        domain: Domain {
            k: 0,
            n: 0,
            n_inv: Fr::zero(),
            gen: Fr::zero(),
            gen_inv: Fr::zero(),
        },
        preprocessed: vec![],
        num_instance: vec![],
        num_witness: vec![],
        num_challenge: vec![],
        evaluations: vec![],
        queries: vec![],
        quotient: QuotientPolynomial {
            chunk_degree: 0,
            numerator: Expression::Challenge(1),
        },
        //Default::default(),
        transcript_initial_state: None,
        instance_committing_key: None,
        linearization: None,
        accumulator_indices: Default::default(),
    }
}
