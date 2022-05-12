use crate::utils::load_randomness_and_circuit;
use anyhow::Error;
use halo2_proofs::plonk::{create_proof, Circuit, ProvingKey};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255};
use pairing::bn256::{Fr, G1Affine};
use zkevm_circuits::evm_circuit::witness::Block;

pub struct Prover {
    pub params: Params<G1Affine>,
    pub rng: XorShiftRng,

    /// evm circuit pk
    pub evm_pk: ProvingKey<G1Affine>,
    /// state circuit pk
    pub state_pk: ProvingKey<G1Affine>,
}

impl Prover {
    pub fn new(
        params: Params<G1Affine>,
        rng: XorShiftRng,
        evm_pk: ProvingKey<G1Affine>,
        state_pk: ProvingKey<G1Affine>,
    ) -> Self {
        Self {
            params,
            rng,
            evm_pk,
            state_pk,
        }
    }

    pub fn create_evm_proof(&self, circuit: impl Circuit<Fr>) -> Result<Vec<u8>, Error> {
        let mut transacript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        create_proof(
            &self.params,
            &self.evm_pk,
            &[circuit],
            &[&[]],
            self.rng,
            &mut transacript,
        )?;
        Ok(transacript.finalize())
    }

    pub fn create_state_proof(&self, circuit: impl Circuit<Fr>) -> Result<Vec<u8>, Error> {
        let power_of_randomness = load_randomness_and_circuit();
        let mut transacript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        create_proof(
            &self.params,
            &self.state_pk,
            &[circuit],
            &[&power_of_randomness],
            self.rng,
            &mut transacript,
        )?;
        Ok(transacript.finalize())
    }
}
