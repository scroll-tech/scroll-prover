use crate::{common, config::LAYER2_DEGREE, Proof};
use aggregator::CompressionCircuit;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};

#[derive(Debug)]
pub struct Verifier {
    inner: common::Verifier,
}

impl From<common::Verifier> for Verifier {
    fn from(inner: common::Verifier) -> Self {
        Self { inner }
    }
}

impl Verifier {
    pub fn new(params: ParamsKZG<Bn256>, vk: VerifyingKey<G1Affine>) -> Self {
        common::Verifier::new(params, vk).into()
    }

    pub fn from_params(params: ParamsKZG<Bn256>, raw_vk: &[u8]) -> Self {
        common::Verifier::from_params(params, raw_vk).into()
    }

    pub fn from_params_dir(params_dir: &str, vk: &[u8]) -> Self {
        common::Verifier::from_params_dir(params_dir, *LAYER2_DEGREE, vk).into()
    }

    pub fn verify_chunk_proof(&self, proof: Proof) -> bool {
        self.inner.verify_proof::<CompressionCircuit>(proof)
    }

    /* TODO: verify inner proof.
        pub fn verify_inner_proof<C: TargetCircuit>(&mut self, snark: &Snark) -> Result<()> {
            let verifier_params = self.inner_params.verifier_params();
            let vk = self.inner_vks.entry(C::name()).or_insert_with(|| {
                let circuit = C::dummy_inner_circuit();
                keygen_vk(&self.inner_params, &circuit)
                    .unwrap_or_else(|_| panic!("Failed to generate {} vk", C::name()))
            });
            if verify_snark_shplonk::<C::Inner>(verifier_params, snark.clone(), vk) {
                Ok(())
            } else {
                bail!("Snark verification failed".to_string())
            }
        }
    */
}
