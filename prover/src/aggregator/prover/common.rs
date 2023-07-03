use super::Prover;
use crate::{
    utils::tick,
    zkevm::circuit::{TargetCircuit, DEGREE},
    Proof,
};
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk2, Circuit, ProvingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use rand::Rng;
use snark_verifier_sdk::{gen_evm_proof_shplonk, gen_pk, gen_snark_shplonk, CircuitExt, Snark};

impl Prover {
    pub(crate) fn gen_snark<C: CircuitExt<Fr>>(
        &mut self,
        id: &str,
        degree: u32,
        rng: &mut (impl Rng + Send),
        circuit: C,
    ) -> Snark {
        let (params, pk) = self.outer_params_and_pk(id, &circuit, degree);

        gen_snark_shplonk(params, pk, circuit, rng, None::<&str>)
    }

    pub(crate) fn gen_evm_proof<C: CircuitExt<Fr>>(
        &mut self,
        id: &str,
        degree: u32,
        rng: &mut (impl Rng + Send),
        circuit: C,
    ) -> Result<Proof> {
        let (params, pk) = self.outer_params_and_pk(id, &circuit, degree);

        let instances = circuit.instances();
        let num_instance = circuit.num_instance();
        let proof = gen_evm_proof_shplonk(params, pk, circuit, instances.clone(), rng);

        Proof::new(proof, pk.get_vk(), &instances, Some(num_instance))
    }

    pub(crate) fn inner_params_and_pk<C: TargetCircuit>(
        &mut self,
        circuit: &<C as TargetCircuit>::Inner,
    ) -> Result<(&ParamsKZG<Bn256>, &ProvingKey<G1Affine>)> {
        let id = C::name();

        // Reuse pk.
        if !self.pk_map.contains_key(&id) {
            tick(&format!("Before generate inner pk of {}", &id));
            let pk = keygen_pk2(self.params(*DEGREE), circuit)?;
            tick(&format!("After generate inner pk of {}", &id));

            self.pk_map.insert(id.clone(), pk);
        }
        assert!(self.params_map.contains_key(&*DEGREE));

        Ok((&self.params_map[&*DEGREE], &self.pk_map[&id]))
    }

    pub(crate) fn params(&mut self, degree: u32) -> &ParamsKZG<Bn256> {
        assert!(degree <= self.max_degree);

        // Reuse params.
        if !self.params_map.contains_key(&degree) {
            tick(&format!("Before generate params of {degree}"));
            let mut new_params = self.max_params().clone();
            new_params.downsize(degree);
            tick(&format!("After generate params of {degree}"));

            self.params_map.insert(degree, new_params);
        }

        &self.params_map[&degree]
    }

    fn max_params(&self) -> &ParamsKZG<Bn256> {
        &self.params_map[&self.max_degree]
    }

    fn outer_params_and_pk<C: Circuit<Fr>>(
        &mut self,
        id: &str,
        circuit: &C,
        degree: u32,
    ) -> (&ParamsKZG<Bn256>, &ProvingKey<G1Affine>) {
        // Reuse pk.
        if !self.pk_map.contains_key(id) {
            tick(&format!("Before generate outer pk of {}", &id));
            let pk = gen_pk(self.params(degree), circuit, None);
            tick(&format!("After generate outer pk of {}", &id));

            self.pk_map.insert(id.to_string(), pk);
        }
        assert!(self.params_map.contains_key(&degree));

        (&self.params_map[&degree], &self.pk_map[id])
    }
}
