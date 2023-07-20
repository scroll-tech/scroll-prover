use crate::{common, config::INNER_DEGREE, utils::load_params, zkevm::circuit::TargetCircuit};
use halo2_proofs::{plonk::keygen_vk, poly::commitment::ParamsProver};
use snark_verifier_sdk::{verify_snark_shplonk, Snark};
use std::marker::PhantomData;

#[derive(Debug)]
pub struct Verifier<C: TargetCircuit> {
    inner: common::Verifier,
    phantom: PhantomData<C>,
}

impl<C: TargetCircuit> From<common::Verifier> for Verifier<C> {
    fn from(inner: common::Verifier) -> Self {
        Self {
            inner,
            phantom: PhantomData,
        }
    }
}

impl<C: TargetCircuit> Verifier<C> {
    pub fn from_params_dir(params_dir: &str) -> Self {
        let params = load_params(params_dir, *INNER_DEGREE, None).unwrap();
        let circuit = C::dummy_inner_circuit();
        let vk = keygen_vk(&params, &circuit)
            .unwrap_or_else(|_| panic!("Failed to generate {} vk", C::name()));

        common::Verifier::new(params, vk).into()
    }

    pub fn verify_inner_snark(&self, snark: Snark) -> bool {
        let verifier_params = self.inner.params().verifier_params();

        verify_snark_shplonk::<C::Inner>(verifier_params, snark, self.inner.vk())
    }
}
