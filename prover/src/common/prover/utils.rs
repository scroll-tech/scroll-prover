use super::Prover;
use crate::Proof;
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk2, Circuit, ProvingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use rand::Rng;
use snark_verifier_sdk::{gen_evm_proof_shplonk, gen_snark_shplonk, CircuitExt, Snark};

impl Prover {
    pub fn gen_snark<C: CircuitExt<Fr>>(
        &mut self,
        id: &str,
        degree: u32,
        rng: &mut (impl Rng + Send),
        circuit: C,
    ) -> Result<Snark> {
        let (params, pk) = self.params_and_pk(id, &circuit, degree)?;

        Ok(gen_snark_shplonk(params, pk, circuit, rng, None::<String>))
    }

    pub fn gen_evm_proof<C: CircuitExt<Fr>>(
        &mut self,
        id: &str,
        degree: u32,
        rng: &mut (impl Rng + Send),
        circuit: C,
    ) -> Result<Proof> {
        let (params, pk) = self.params_and_pk(id, &circuit, degree)?;

        let instances = circuit.instances();
        let num_instance = circuit.num_instance();
        let proof = gen_evm_proof_shplonk(params, pk, circuit, instances.clone(), rng);

        Proof::new(pk, proof, &instances, Some(num_instance))
    }

    pub fn params(&mut self, degree: u32) -> &ParamsKZG<Bn256> {
        if self.params_map.contains_key(&degree) {
            return &self.params_map[&degree];
        }

        log::warn!("Optimization: download params{degree} to params dir");

        log::info!("Before generate params of {degree}");
        let mut new_params = self
            .params_map
            .range(degree..)
            .next()
            .unwrap_or_else(|| panic!("Must have params of degree-{degree}"))
            .1
            .clone();
        new_params.downsize(degree);
        log::info!("After generate params of {degree}");

        self.params_map.insert(degree, new_params);
        &self.params_map[&degree]
    }

    pub fn pk(&self, id: &str) -> Option<&ProvingKey<G1Affine>> {
        self.pk_map.get(id)
    }

    pub fn params_and_pk<C: Circuit<Fr>>(
        &mut self,
        id: &str,
        circuit: &C,
        degree: u32,
    ) -> Result<(&ParamsKZG<Bn256>, &ProvingKey<G1Affine>)> {
        // Reuse pk.
        if self.pk_map.contains_key(id) {
            return Ok((&self.params_map[&degree], &self.pk_map[id]));
        }

        log::info!("Before generate pk of {}", &id);
        let pk = keygen_pk2(self.params(degree), circuit)?;
        log::info!("After generate pk of {}", &id);

        self.pk_map.insert(id.to_string(), pk);

        Ok((&self.params_map[&degree], &self.pk_map[id]))
    }
}
