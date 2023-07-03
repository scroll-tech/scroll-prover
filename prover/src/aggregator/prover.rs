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

#[derive(Debug)]
pub struct Prover {
    max_degree: u32,
    // Cached degree -> params
    params_map: HashMap<u32, ParamsKZG<Bn256>>,
    // Cached id -> pk
    pk_map: HashMap<String, ProvingKey<G1Affine>>,
}

impl Prover {
    pub fn from_params(max_degree: u32, init_params: ParamsKZG<Bn256>) -> Self {
        Self {
            max_degree,
            params_map: HashMap::from([(max_degree, init_params)]),
            pk_map: HashMap::new(),
        }
    }
}
