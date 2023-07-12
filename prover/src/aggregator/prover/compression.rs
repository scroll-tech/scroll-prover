use super::Prover;
use crate::Proof;
use aggregator::CompressionCircuit;
use anyhow::{anyhow, Result};
use rand::Rng;
use snark_verifier_sdk::Snark;

impl Prover {
    pub fn gen_comp_snark(
        &mut self,
        id: &str,
        is_fresh: bool,
        degree: u32,
        mut rng: impl Rng + Send,
        prev_snark: Snark,
    ) -> Result<Snark> {
        let circuit = CompressionCircuit::new(self.params(degree), prev_snark, is_fresh, &mut rng)
            .map_err(|err| anyhow!("Failed to construct compression circuit: {err:?}"))?;

        self.gen_snark(id, degree, &mut rng, circuit)
    }

    pub fn gen_comp_evm_proof(
        &mut self,
        id: &str,
        is_fresh: bool,
        degree: u32,
        mut rng: impl Rng + Send,
        prev_snark: Snark,
    ) -> Result<Proof> {
        let circuit = CompressionCircuit::new(self.params(degree), prev_snark, is_fresh, &mut rng)
            .map_err(|err| anyhow!("Failed to construct compression circuit: {err:?}"))?;

        self.gen_evm_proof(id, degree, &mut rng, circuit)
    }
}
