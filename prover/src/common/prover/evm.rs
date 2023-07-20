use super::Prover;
use crate::{utils::gen_rng, Proof};
use aggregator::CompressionCircuit;
use anyhow::{anyhow, Result};
use halo2_proofs::halo2curves::bn256::Fr;
use rand::Rng;
use snark_verifier_sdk::{gen_evm_proof_shplonk, CircuitExt, Snark};
use std::{env::set_var, path::PathBuf};

impl Prover {
    pub fn load_or_gen_comp_evm_proof(
        &mut self,
        name: &str,
        id: &str,
        is_fresh: bool,
        degree: u32,
        prev_snark: Snark,
        output_dir: Option<&str>,
    ) -> Result<Proof> {
        let file_path = format!(
            "{}/{}_full_proof.json",
            output_dir.unwrap_or_default(),
            name
        );

        match output_dir.and_then(|_| Proof::from_json_file(&file_path).ok().flatten()) {
            Some(proof) => Ok(proof),
            None => {
                set_var("COMPRESSION_CONFIG", format!("./configs/{id}.config"));

                let mut rng = gen_rng();
                let circuit =
                    CompressionCircuit::new(self.params(degree), prev_snark, is_fresh, &mut rng)
                        .map_err(|err| {
                            anyhow!("Failed to construct compression circuit: {err:?}")
                        })?;

                let result = self.gen_evm_proof(id, degree, &mut rng, circuit);

                if let (Some(output_dir), Ok(proof)) = (output_dir, &result) {
                    proof.dump(&mut PathBuf::from(output_dir), name)?;
                }

                result
            }
        }
    }

    fn gen_evm_proof<C: CircuitExt<Fr>>(
        &mut self,
        id: &str,
        degree: u32,
        rng: &mut (impl Rng + Send),
        circuit: C,
    ) -> Result<Proof> {
        Self::assert_if_mock_prover(id, degree, &circuit);

        let (params, pk) = self.params_and_pk(id, &circuit, degree)?;

        let instances = circuit.instances();
        let num_instance = circuit.num_instance();
        let proof = gen_evm_proof_shplonk(params, pk, circuit, instances.clone(), rng);

        Proof::new(pk, proof, &instances, Some(num_instance))
    }
}
