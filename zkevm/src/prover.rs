use crate::circuit::block_result_to_circuits;
use crate::keygen::{gen_evm_pk, gen_state_pk};
use crate::utils::{init_params, init_rng};
use anyhow::Error;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::plonk::{create_proof, ProvingKey};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255};
use pairing::bn256::{Fr, G1Affine};
use rand_xorshift::XorShiftRng;
use types::eth::test::mock_block_result;
use zkevm_circuits::evm_circuit::param::STEP_HEIGHT;

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

    pub fn with_fpath(params_fpath: &str, seed_fpath: &str) -> Self {
        let params = init_params(params_fpath);
        let rng = init_rng(seed_fpath);
        let evm_pk = gen_evm_pk(&params).expect("Failed to generate evm proving key");
        let state_pk = gen_state_pk(&params).expect("Failed to generate state proving key");
        Self {
            params,
            rng,
            evm_pk,
            state_pk,
        }
    }

    pub fn create_evm_proof(&self) -> Result<Vec<u8>, Error> {
        let block_result = mock_block_result();
        let (_, circuit, _) = block_result_to_circuits::<Fr>(block_result)?;
        let mut transacript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        create_proof(
            &self.params,
            &self.evm_pk,
            &[circuit],
            &[&[]],
            self.rng.clone(),
            &mut transacript,
        )?;
        Ok(transacript.finalize())
    }

    pub fn create_state_proof(&self) -> Result<Vec<u8>, Error> {
        let block_result = mock_block_result();
        let (block, _, circuit) = block_result_to_circuits::<Fr>(block_result).unwrap();
        let power_of_randomness: Vec<Box<[Fr]>> = (1..32)
            .map(|exp| {
                vec![
                    block.randomness.pow(&[exp, 0, 0, 0]);
                    block.txs.iter().map(|tx| tx.steps.len()).sum::<usize>() * STEP_HEIGHT
                ]
                .into_boxed_slice()
            })
            .collect();
        let randomness: Vec<_> = power_of_randomness.iter().map(AsRef::as_ref).collect();

        let mut transacript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        create_proof(
            &self.params,
            &self.state_pk,
            &[circuit],
            &[&randomness],
            self.rng.clone(),
            &mut transacript,
        )?;
        Ok(transacript.finalize())
    }
}
