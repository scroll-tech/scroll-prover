use crate::io::{deserialize_fr_matrix, serialize_fr_matrix, write_file};
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::{Circuit, ProvingKey, VerifyingKey},
    SerdeFormat,
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
    io::Cursor,
    path::{Path, PathBuf},
};
use types::base64;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Proof {
    #[serde(with = "base64")]
    proof: Vec<u8>,
    #[serde(with = "base64")]
    vk: Vec<u8>,
    #[serde(with = "base64")]
    instances: Vec<u8>,
    // Only for EVM proof.
    num_instance: Option<Vec<usize>>,
}

impl Proof {
    pub fn new(
        proof: Vec<u8>,
        original_vk: &VerifyingKey<G1Affine>,
        instances: &[Vec<Fr>],
        num_instance: Option<Vec<usize>>,
    ) -> Result<Self> {
        let mut vk = Vec::<u8>::new();
        original_vk.write(&mut vk, SerdeFormat::Processed)?;

        let instances = serde_json::to_vec(&serialize_fr_matrix(instances))?;

        Ok(Self {
            proof,
            vk,
            instances,
            num_instance,
        })
    }

    pub fn from_json_file(file_path: &str) -> Result<Option<Self>> {
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

    pub fn dump(&self, dir: &mut PathBuf, name: &str) -> Result<()> {
        write_file(dir, &format!("{name}_proof.data"), &self.proof);
        write_file(dir, &format!("{name}.vkey"), &self.vk);
        write_file(dir, &format!("{name}_instances.data"), &self.instances);

        dir.push(format!("{name}_full_proof.json"));
        let mut fd = std::fs::File::create(dir.as_path())?;
        dir.pop();
        serde_json::to_writer_pretty(&mut fd, &self)?;

        Ok(())
    }

    pub fn from_snark(pk: &ProvingKey<G1Affine>, snark: &Snark) -> Result<Self> {
        let mut vk = Vec::<u8>::new();
        pk.get_vk().write(&mut vk, SerdeFormat::Processed)?;

        let instances = serialize_fr_matrix(snark.instances.as_slice());
        let instances = serde_json::to_vec(&instances)?;

        Ok(Proof {
            proof: snark.proof.clone(),
            vk,
            instances,
            num_instance: None,
        })
    }

    pub fn to_snark(&self) -> Snark {
        Snark {
            protocol: dummy_protocol(),
            proof: self.proof.clone(),
            instances: self.instances(),
        }
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    pub fn vk<C: Circuit<Fr>>(&self) -> Result<VerifyingKey<G1Affine>> {
        Ok(VerifyingKey::<G1Affine>::read::<_, C>(
            &mut Cursor::new(&self.vk),
            SerdeFormat::Processed,
        )?)
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        let buf: Vec<Vec<Vec<_>>> = serde_json::from_reader(self.instances.as_slice()).unwrap();

        deserialize_fr_matrix(buf)
    }

    pub fn num_instance(&self) -> Option<&Vec<usize>> {
        self.num_instance.as_ref()
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
