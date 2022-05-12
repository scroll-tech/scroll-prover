use crate::circuit::block_result_to_circuits;
use crate::keygen::{gen_evm_vk, gen_state_vk};
use crate::utils::init_params;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::{SingleVerifier, VerifyingKey};
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::transcript::{Blake2bRead, Challenge255};
use pairing::bn256::{Bn256, Fr, G1Affine};
use types::eth::test::mock_block_result;
use zkevm_circuits::evm_circuit::param::STEP_HEIGHT;

pub struct Verifier {
    params: Params<G1Affine>,
    evm_vk: VerifyingKey<G1Affine>,
    state_vk: VerifyingKey<G1Affine>,
}

impl Verifier {
    pub fn new(
        params: Params<G1Affine>,
        evm_vk: VerifyingKey<G1Affine>,
        state_vk: VerifyingKey<G1Affine>,
    ) -> Self {
        Self {
            params,
            evm_vk,
            state_vk,
        }
    }
    pub fn with_fpath(params_path: &str) -> Self {
        let params = init_params(params_path);
        let evm_vk = gen_evm_vk(&params).expect("Failed to generate evm verifier key");
        let state_vk = gen_state_vk(&params).expect("Failed to generate state verifier key");
        Self {
            params,
            evm_vk,
            state_vk,
        }
    }

    pub fn verify_evm_proof(&self, proof: Vec<u8>) -> bool {
        let block_result = mock_block_result();
        let (block, _, _) = block_result_to_circuits::<Fr>(block_result).unwrap();
        let power_of_randomness: Vec<Box<[Fr]>> = (1..32)
            .map(|exp| {
                vec![
                    block.randomness.pow(&[exp, 0, 0, 0]);
                    block.txs.iter().map(|tx| tx.steps.len()).sum::<usize>() * STEP_HEIGHT
                ]
                .into_boxed_slice()
            })
            .collect();

        let verifier_params: ParamsVerifier<Bn256> =
            self.params.verifier(power_of_randomness[0].len()).unwrap();

        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleVerifier::new(&verifier_params);

        verify_proof(
            &verifier_params,
            &self.evm_vk,
            strategy,
            &[&[]],
            &mut transcript,
        )
        .is_ok()
    }

    pub fn verify_state_proof(&self, proof: Vec<u8>) -> bool {
        let block_result = mock_block_result();
        let (block, _, _) = block_result_to_circuits::<Fr>(block_result).unwrap();
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

        let verifier_params: ParamsVerifier<Bn256> =
            self.params.verifier(power_of_randomness[0].len()).unwrap();

        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleVerifier::new(&verifier_params);

        verify_proof(
            &verifier_params,
            &self.state_vk,
            strategy,
            &[&randomness],
            &mut transcript,
        )
        .is_ok()
    }
}
