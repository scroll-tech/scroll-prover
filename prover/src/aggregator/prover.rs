use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use std::collections::HashMap;

mod aggregation;
mod chunk;
mod common;
mod compression;
mod utils;

#[derive(Debug)]
pub struct Prover {
    params: ParamsKZG<Bn256>,
    pks: HashMap<String, ProvingKey<G1Affine>>,
}
