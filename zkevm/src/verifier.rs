use std::collections::HashMap;
use std::io::Cursor;

use crate::circuit::{
    ByteCodeCircuit, EvmCircuit, PoseidonCircuit, StateCircuit, TargetCircuit, ZktrieCircuit,
    AGG_DEGREE, DEGREE,
};
use crate::io::{deserialize_fr_matrix, load_instances};
use crate::prover::{AggCircuitProof, TargetCircuitProof};
use crate::utils::load_params;
use halo2_proofs::pairing::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{keygen_vk, verify_proof};
use halo2_proofs::plonk::{SingleVerifier, VerifyingKey};
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::transcript::{Challenge255, PoseidonRead};
use halo2_snark_aggregator_api::transcript::sha::ShaRead;
use halo2_snark_aggregator_circuit::verify_circuit::Halo2VerifierCircuit;

pub struct Verifier {
    params: Params<G1Affine>,
    agg_params: Params<G1Affine>,
    // just for legacy testing code...
    raw_agg_vk: Option<Vec<u8>>,
    agg_vk: Option<VerifyingKey<G1Affine>>,
    target_circuit_vks: HashMap<String, VerifyingKey<G1Affine>>,
}

impl Verifier {
    pub fn new(
        params: Params<G1Affine>,
        agg_params: Params<G1Affine>,
        raw_agg_vk: Option<Vec<u8>>,
    ) -> Self {
        if raw_agg_vk.is_none() {
            log::error!("Verifier should better have raw_agg_vk to check consistency");
        }
        let agg_vk = raw_agg_vk.as_ref().map(|k| {
            VerifyingKey::<G1Affine>::read::<_, Halo2VerifierCircuit<'_, Bn256>>(
                &mut Cursor::new(&k),
                &agg_params,
            )
            .unwrap()
        });
        let mut verifier = Self {
            params,
            agg_params,
            agg_vk,
            raw_agg_vk,
            target_circuit_vks: Default::default(),
        };
        verifier.init_vk::<EvmCircuit>();
        verifier.init_vk::<StateCircuit>();
        verifier.init_vk::<ZktrieCircuit>();
        verifier.init_vk::<PoseidonCircuit>();
        verifier.init_vk::<ByteCodeCircuit>();
        verifier
    }

    fn init_vk<C: TargetCircuit>(&mut self) {
        let circuit = C::empty();
        let vk = keygen_vk(&self.params, &circuit)
            .unwrap_or_else(|_| panic!("failed to generate {} vk", C::name()));
        self.target_circuit_vks.insert(C::name(), vk);
    }

    pub fn from_params(
        params: Params<G1Affine>,
        agg_params: Params<G1Affine>,
        agg_vk: Option<Vec<u8>>,
    ) -> Self {
        Self::new(params, agg_params, agg_vk)
    }

    pub fn from_fpath(params_path: &str, agg_vk: Option<Vec<u8>>) -> Self {
        let params = load_params(params_path, *DEGREE).expect("failed to init params");
        let agg_params = load_params(params_path, *AGG_DEGREE).expect("failed to init params");
        Self::from_params(params, agg_params, agg_vk)
    }

    pub fn verify_agg_circuit_proof(&self, proof: AggCircuitProof) -> anyhow::Result<()> {
        if let Some(raw_agg_vk) = &self.raw_agg_vk {
            if &proof.vk != raw_agg_vk {
                log::error!("vk provided in proof != vk in verifier");
            }
        }
        let verify_circuit_instance: Vec<Vec<Vec<Fr>>> = {
            let instance = proof.instance;
            load_instances(&instance)
        };
        let limbs = 4;
        let params = self.agg_params.verifier::<Bn256>(limbs * 4).unwrap();
        let strategy = SingleVerifier::new(&params);

        let verify_circuit_instance1: Vec<Vec<&[Fr]>> = verify_circuit_instance
            .iter()
            .map(|x| x.iter().map(|y| &y[..]).collect())
            .collect();
        let verify_circuit_instance2: Vec<&[&[Fr]]> =
            verify_circuit_instance1.iter().map(|x| &x[..]).collect();

        let mut transcript = ShaRead::<_, _, Challenge255<_>, sha2::Sha256>::init(&proof.proof[..]);

        // TODO better way to do this?
        let vk_in_proof = VerifyingKey::<G1Affine>::read::<_, Halo2VerifierCircuit<'_, Bn256>>(
            &mut Cursor::new(&proof.vk),
            &self.agg_params,
        )
        .unwrap();
        verify_proof(
            &params,
            self.agg_vk.as_ref().unwrap_or(&vk_in_proof),
            strategy,
            &verify_circuit_instance2[..],
            &mut transcript,
        )?;
        Ok(())
    }

    pub fn verify_target_circuit_proof<C: TargetCircuit>(
        &self,
        proof: &TargetCircuitProof,
    ) -> anyhow::Result<()> {
        let instances: Vec<Vec<Vec<u8>>> = serde_json::from_reader(&proof.instance[..])?;
        let instances = deserialize_fr_matrix(instances);

        let instance_slice = instances.iter().map(|x| &x[..]).collect::<Vec<_>>();

        // TODO: is this correct? OR MAX?
        let public_input_len = instance_slice
            .iter()
            .map(|col| col.len())
            .max()
            .unwrap_or(0);

        let verifier_params: ParamsVerifier<Bn256> =
            self.params.verifier(public_input_len).unwrap();

        let mut transcript = PoseidonRead::<_, _, Challenge255<_>>::init(&proof.proof[..]);
        let strategy = SingleVerifier::new(&verifier_params);
        let vk = &self.target_circuit_vks[&C::name()];
        verify_proof(
            &verifier_params,
            vk,
            strategy,
            &[instance_slice.as_slice()],
            &mut transcript,
        )?;
        Ok(())
    }
}
