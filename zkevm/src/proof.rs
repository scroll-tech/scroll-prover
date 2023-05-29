use crate::io::{
    serialize_fr_matrix, serialize_instance, serialize_vk,
    write_verify_circuit_instance, write_verify_circuit_proof, write_verify_circuit_vk, load_instance, deserialize_fr_matrix,
};
use anyhow::Result;
use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_proofs::plonk::ProvingKey;
use serde_derive::{Deserialize, Serialize};
use snark_verifier::Protocol;
use snark_verifier::util::{
    arithmetic::Domain,
    protocol::{Expression,QuotientPolynomial},
};
use snark_verifier_sdk::{gen_pk, CircuitExt, Snark};
use zkevm_circuits::util::Expr;
use std::{path::PathBuf, default};
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
        let l3_buf: Vec<Vec<Vec<u8>>> = serde_json::from_reader(self.instance.as_slice()).unwrap();
        let instances = deserialize_fr_matrix(l3_buf);
        Snark {
            protocol: dummy_protocol(),
            instances: instances,
            proof: self.proof.clone(),
        }
    }

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
