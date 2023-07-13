use super::Prover;
use crate::{utils::gen_rng, Proof};
use aggregator::CompressionCircuit;
use anyhow::{anyhow, Result};
use snark_verifier_sdk::Snark;
use std::{env::set_var, path::PathBuf};

impl Prover {
    pub fn gen_comp_evm_proof(
        &mut self,
        name: &str,
        id: &str,
        is_fresh: bool,
        degree: u32,
        prev_snark: Snark,
        output_dir: Option<&str>,
    ) -> Result<Proof> {
        set_var("COMPRESSION_CONFIG", format!("./configs/{id}.config"));

        let mut rng = gen_rng();
        let circuit = CompressionCircuit::new(self.params(degree), prev_snark, is_fresh, &mut rng)
            .map_err(|err| anyhow!("Failed to construct compression circuit: {err:?}"))?;

        let result = self.gen_evm_proof(id, degree, &mut rng, circuit);

        if let (Some(output_dir), Ok(proof)) = (output_dir, &result) {
            proof.dump(&mut PathBuf::from(output_dir), name)?;
        }

        result
    }
}
