//! Aggregate the proofs.

use halo2_proofs::{
    circuit::Value,
    halo2curves::bn256::{Fr, G1Affine},
};
use snark_verifier::Protocol;

mod circuit;
mod sub_circuit;

#[derive(Clone, Debug)]
pub struct SnarkWitness {
    pub protocol: Protocol<G1Affine>,
    pub instances: Vec<Vec<Value<Fr>>>,
    pub proof: Value<Vec<u8>>,
}
