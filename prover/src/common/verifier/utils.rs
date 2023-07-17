use super::Verifier;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};

impl Verifier {
    pub fn params(&self) -> &ParamsKZG<Bn256> {
        &self.params
    }

    pub fn vk(&self) -> Option<&VerifyingKey<G1Affine>> {
        self.vk.as_ref()
    }
}
