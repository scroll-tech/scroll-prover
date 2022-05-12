use crate::utils::load_randomness_and_circuit;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::{SingleVerifier, VerifyingKey};
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::transcript::{Blake2bRead, Challenge255};
use pairing::bn256::{Bn256, G1Affine, G1};

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

    pub fn verify_evm_proof(&self, proof: Vec<u8>) -> bool {
        let power_of_randomness = load_randomness_and_circuit();
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
        let power_of_randomness = load_randomness_and_circuit();
        let verifier_params: ParamsVerifier<Bn256> =
            self.params.verifier(power_of_randomness[0].len()).unwrap();

        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleVerifier::new(&verifier_params);

        verify_proof(
            &verifier_params,
            &self.state_vk,
            strategy,
            &[&power_of_randomness],
            &mut transcript,
        )
        .is_ok()
    }
}
