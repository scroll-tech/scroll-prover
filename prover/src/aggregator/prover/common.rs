use super::{utils::tick, Prover};
use crate::zkevm::circuit::TargetCircuit;
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    plonk::keygen_pk2,
    poly::kzg::commitment::ParamsKZG,
};
use rand::Rng;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, verify_snark_shplonk, CircuitExt, Snark};

impl Prover {
    pub(crate) fn gen_snark(
        &mut self,
        id: &str,
        rng: &mut (impl Rng + Send),
        params: &ParamsKZG<Bn256>,
        circuit: impl CircuitExt<Fr> + Clone,
    ) -> Snark {
        // Reuse pk.
        if !self.pks.contains_key(id) {
            self.gen_outer_pk(id, params, circuit.clone());
        }
        let pk = &self.pks[id];

        gen_snark_shplonk(params, pk, circuit, rng, None::<&str>)
    }

    pub(crate) fn verify_snark<C: CircuitExt<Fr>>(
        &self,
        id: &str,
        params: &ParamsKZG<Bn256>,
        snark: Snark,
    ) -> bool {
        // Must have cached pk.
        let pk = &self.pks[id];

        verify_snark_shplonk::<C>(params, snark, pk.get_vk())
    }

    pub(crate) fn gen_inner_pk<C: TargetCircuit>(
        &mut self,
        circuit: &<C as TargetCircuit>::Inner,
    ) -> Result<()> {
        let id = C::name();

        tick(&format!("Before generate inner pk of {}", &id));
        let pk = keygen_pk2(&self.params, circuit)?;
        tick(&format!("After generate inner pk of {}", &id));

        self.pks.insert(id, pk);

        Ok(())
    }

    fn gen_outer_pk(&mut self, id: &str, params: &ParamsKZG<Bn256>, circuit: impl CircuitExt<Fr>) {
        tick(&format!("Before generate outer pk of {}", &id));
        let pk = gen_pk(params, &circuit, None);
        tick(&format!("After generate outer pk of {}", &id));

        self.pks.insert(id.to_string(), pk);
    }
}
