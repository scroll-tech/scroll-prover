use std::collections::HashMap;
use std::path::PathBuf;

use crate::circuit::{
    EvmCircuit, PoseidonCircuit, StateCircuit, TargetCircuit, ZktrieCircuit, AGG_DEGREE, DEGREE,
};
use crate::io::{
    deserialize_fr_matrix, serialize_fr_tensor, serialize_instance,
    serialize_verify_circuit_final_pair, serialize_vk, write_verify_circuit_final_pair,
    write_verify_circuit_instance, write_verify_circuit_proof, write_verify_circuit_vk,
};
use crate::utils::load_seed;
use crate::utils::{load_or_create_params, read_env_var};
use anyhow::{bail, Error};
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::poly::kzg::multiopen::ProverGWC;
use halo2_proofs::transcript::{Challenge255, PoseidonWrite};
use halo2_snark_aggregator_api::transcript::sha::ShaWrite;
use halo2_snark_aggregator_circuit::verify_circuit::{
    final_pair_to_instances, Halo2CircuitInstance, Halo2CircuitInstances, Halo2VerifierCircuit,
    Halo2VerifierCircuits, SingleProofWitness,
};
use log::info;
use once_cell::sync::Lazy;

use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use serde_derive::{Deserialize, Serialize};
use types::base64;
use types::eth::BlockResult;

#[cfg(target_os = "linux")]
extern crate procfs;

pub static OPT_MEM: Lazy<bool> = Lazy::new(|| read_env_var("OPT_MEM", false));
pub static MOCK_PROVE: Lazy<bool> = Lazy::new(|| read_env_var("MOCK_PROVE", false));

#[derive(Deserialize, Serialize, Debug)]
pub struct TargetCircuitProof {
    pub name: String,
    #[serde(with = "base64")]
    pub proof: Vec<u8>,
    #[serde(with = "base64")]
    pub instance: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug, Default)]
pub struct AggCircuitProof {
    #[serde(with = "base64")]
    pub proof: Vec<u8>,

    #[serde(with = "base64")]
    pub instance: Vec<u8>,

    #[serde(with = "base64")]
    pub final_pair: Vec<u8>,

    #[serde(with = "base64")]
    pub vk: Vec<u8>,
}

pub struct ProvedCircuit {
    pub name: String,
    pub transcript: Vec<u8>,
    pub vk: VerifyingKey<G1Affine>,
    pub instance: Vec<Vec<Vec<Fr>>>,
}

impl AggCircuitProof {
    pub fn write_to_dir(&self, out_dir: &mut PathBuf) {
        write_verify_circuit_final_pair(out_dir, &self.final_pair);
        write_verify_circuit_instance(out_dir, &self.instance);
        write_verify_circuit_proof(out_dir, &self.proof);
        write_verify_circuit_vk(out_dir, &self.vk);

        out_dir.push("full_proof.data");
        let mut fd = std::fs::File::create(out_dir.as_path()).unwrap();
        out_dir.pop();
        serde_json::to_writer_pretty(&mut fd, &self).unwrap()
    }
}

#[derive(Debug)]
pub struct Prover {
    pub params: ParamsKZG<Bn256>,
    pub agg_params: ParamsKZG<Bn256>,
    pub rng: XorShiftRng,

    pub target_circuit_pks: HashMap<String, ProvingKey<G1Affine>>,
    pub agg_pk: Option<ProvingKey<G1Affine>>,
    //pub target_circuit_vks: HashMap<String, ProvingKey<G1Affine>>,
}

impl Prover {
    pub fn new(params: ParamsKZG<Bn256>, agg_params: ParamsKZG<Bn256>, rng: XorShiftRng) -> Self {
        Self {
            params,
            agg_params,
            rng,
            target_circuit_pks: Default::default(),
            agg_pk: None,
        }
    }

    fn tick(desc: &str) {
        #[cfg(target_os = "linux")]
        let memory = match procfs::Meminfo::new() {
            Ok(m) => m.mem_total - m.mem_free,
            Err(_) => 0,
        };
        #[cfg(not(target_os = "linux"))]
        let memory = 0;
        log::debug!(
            "memory usage when {}: {:?}GB",
            desc,
            memory / 1024 / 1024 / 1024
        );
    }

    fn init_pk<C: TargetCircuit>(&mut self) {
        Self::tick(&format!("before init pk of {}", C::name()));
        let circuit = C::empty();
        let vk = keygen_vk(&self.params, &circuit)
            .unwrap_or_else(|_| panic!("failed to generate {} vk", C::name()));
        let pk = keygen_pk(&self.params, vk, &circuit)
            .unwrap_or_else(|_| panic!("failed to generate {} pk", C::name()));
        self.target_circuit_pks.insert(C::name(), pk);
        Self::tick(&format!("after init pk of {}", C::name()));
    }

    pub fn from_params_and_rng(
        params: ParamsKZG<Bn256>,
        agg_params: ParamsKZG<Bn256>,
        rng: XorShiftRng,
    ) -> Self {
        Self::new(params, agg_params, rng)
    }

    pub fn from_params_and_seed(
        params: ParamsKZG<Bn256>,
        agg_params: ParamsKZG<Bn256>,
        seed: [u8; 16],
    ) -> Self {
        let rng = XorShiftRng::from_seed(seed);
        Self::from_params_and_rng(params, agg_params, rng)
    }

    pub fn from_fpath(params_fpath: &str, seed_fpath: &str) -> Self {
        let params = load_or_create_params(params_fpath, *DEGREE).expect("failed to init params");
        let agg_params =
            load_or_create_params(params_fpath, *AGG_DEGREE).expect("failed to init params");
        let seed = load_seed(seed_fpath).expect("failed to init rng");
        let rng = XorShiftRng::from_seed(seed);
        // FIXME check params
        {
            let target_params_verifier: &ParamsVerifierKZG<Bn256> = params.verifier_params();
            let agg_params_verifier: &ParamsVerifierKZG<Bn256> = agg_params.verifier_params();
            log::info!(
                "params g2 {:?} s_g2 {:?}",
                target_params_verifier.g2(),
                target_params_verifier.s_g2()
            );
            debug_assert_eq!(target_params_verifier.s_g2(), agg_params_verifier.s_g2());
            debug_assert_eq!(target_params_verifier.g2(), agg_params_verifier.g2());
        }
        Self::from_params_and_rng(params, agg_params, rng)
    }

    fn prove_circuit<C: TargetCircuit>(
        &mut self,
        block_results: &[BlockResult],
    ) -> anyhow::Result<ProvedCircuit> {
        let proof = self.create_target_circuit_proof_multi::<C>(block_results)?;

        let instances: Vec<Vec<Vec<u8>>> = serde_json::from_reader(&proof.instance[..])?;
        let instances = deserialize_fr_matrix(instances);
        debug_assert!(instances.is_empty(), "instance not supported yet");
        let vk = self.target_circuit_pks[&proof.name].get_vk().clone();
        if *OPT_MEM {
            Self::tick(&format!("before release pk of {}", C::name()));
            self.target_circuit_pks.remove(&C::name());
            Self::tick(&format!("after release pk of {}", &C::name()));
        }

        Ok(ProvedCircuit {
            name: proof.name.clone(),
            transcript: proof.proof,
            vk,
            instance: vec![instances],
        })
    }

    pub fn create_agg_circuit_proof(
        &mut self,
        block_result: &BlockResult,
    ) -> anyhow::Result<AggCircuitProof> {
        self.create_agg_circuit_proof_multi(&[block_result.clone()])
    }

    pub fn create_agg_circuit_proof_multi(
        &mut self,
        block_results: &[BlockResult],
    ) -> anyhow::Result<AggCircuitProof> {
        let circuit_results: Vec<ProvedCircuit> = vec![
            self.prove_circuit::<EvmCircuit>(block_results)?,
            self.prove_circuit::<StateCircuit>(block_results)?,
            self.prove_circuit::<PoseidonCircuit>(block_results)?,
            self.prove_circuit::<ZktrieCircuit>(block_results)?,
        ];
        self.create_agg_circuit_proof_impl(circuit_results)
    }

    fn create_agg_circuit_proof_impl(
        &mut self,
        circuit_results: Vec<ProvedCircuit>,
    ) -> anyhow::Result<AggCircuitProof> {
        ///////////////////////////// build verifier circuit from block result ///////////////////
        // commitments of rw table columns of evm circuit should be same as commitments of rw table columns of state circuit
        let evm_circuit_idx = 0;
        let state_circuit_idx = 1;
        let rw_table_start_evm = 0;
        let rw_table_start_state = 0;
        let rw_table_commitments_len = 11;

        let mut coherent = Vec::new();
        for i in 0..rw_table_commitments_len {
            coherent.push([
                (evm_circuit_idx, rw_table_start_evm + i),
                (state_circuit_idx, rw_table_start_state + i),
            ]);
        }

        let verifier_params = self.params.verifier_params();
        let verify_circuit = Halo2VerifierCircuits::<'_, Bn256, 4> {
            circuits: [0, 1, 2, 3].map(|i| {
                let c = &circuit_results[i];
                Halo2VerifierCircuit::<'_, Bn256> {
                    name: c.name.clone(),
                    nproofs: 1,
                    proofs: vec![SingleProofWitness::<'_, Bn256> {
                        instances: &c.instance,
                        transcript: &c.transcript,
                    }],
                    vk: &c.vk,
                    params: verifier_params,
                }
            }),
            coherent,
        };
        ///////////////////////////// build verifier circuit from block result done ///////////////////
        let n_instances = [0, 1, 2, 3].map(|i| vec![circuit_results[i].instance.clone()]);
        let n_transcript = [0, 1, 2, 3].map(|i| vec![circuit_results[i].transcript.clone()]);
        let instances: [Halo2CircuitInstance<'_, Bn256>; 4] =
            [0, 1, 2, 3].map(|i| Halo2CircuitInstance {
                name: circuit_results[i].name.clone(),
                params: verifier_params,
                vk: &circuit_results[i].vk,
                n_instances: &n_instances[i],
                n_transcript: &n_transcript[i],
            });
        let verify_circuit_final_pair =
            Halo2CircuitInstances::<'_, Bn256, 4>(instances).calc_verify_circuit_final_pair();
        let verify_circuit_instances =
            final_pair_to_instances::<_, Bn256>(&verify_circuit_final_pair);

        if self.agg_pk.is_none() {
            log::info!("init_agg_pk: init from verifier circuit");

            let verify_circuit_vk =
                keygen_vk(&self.agg_params, &verify_circuit).expect("keygen_vk should not fail");

            let verify_circuit_pk = keygen_pk(&self.agg_params, verify_circuit_vk, &verify_circuit)
                .expect("keygen_pk should not fail");
            self.agg_pk = Some(verify_circuit_pk);

            log::info!("init_agg_pk: init done");
        } else {
            log::info!("using existing agg_pk");
        }

        let instances_slice: &[&[&[Fr]]] = &[&[&verify_circuit_instances[..]]];
        let mut transcript = ShaWrite::<_, G1Affine, Challenge255<_>, sha2::Sha256>::init(vec![]);

        if *MOCK_PROVE {
            log::info!("mock prove agg circuit");
            let prover = MockProver::<Fr>::run(
                *AGG_DEGREE as u32,
                &verify_circuit,
                vec![verify_circuit_instances.clone()],
            )?;
            if let Err(e) = prover.verify_par() {
                bail!("{:#?}", e);
            }
            log::info!("mock prove agg circuit done");
        }
        log::info!("create agg proof");
        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
            &self.agg_params,
            self.agg_pk.as_ref().unwrap(),
            &[verify_circuit],
            instances_slice,
            self.rng.clone(),
            &mut transcript,
        )?;
        log::info!("create agg proof done");

        let proof = transcript.finalize();

        let instances_for_serde = serialize_fr_tensor(&[vec![verify_circuit_instances]]);
        let instance_bytes = serde_json::to_vec(&instances_for_serde)?;
        let vk_bytes = serialize_vk(self.agg_pk.as_ref().expect("pk should be inited").get_vk());
        let final_pair = serialize_verify_circuit_final_pair(&verify_circuit_final_pair);
        Ok(AggCircuitProof {
            proof,
            instance: instance_bytes,
            final_pair,
            vk: vk_bytes,
        })
    }

    pub fn mock_prove_target_circuit<C: TargetCircuit>(
        block_result: &BlockResult,
        full: bool,
    ) -> anyhow::Result<()> {
        Self::mock_prove_target_circuit_multi::<C>(&[block_result.clone()], full)
    }

    pub fn mock_prove_target_circuit_multi<C: TargetCircuit>(
        block_results: &[BlockResult],
        full: bool,
    ) -> anyhow::Result<()> {
        log::info!("start mock prove {}", C::name());
        let (circuit, instance) = C::from_block_results(block_results)?;
        let prover = MockProver::<Fr>::run(*DEGREE as u32, &circuit, instance)?;
        if !full {
            // FIXME for packing
            let (gate_rows, lookup_rows) = C::get_active_rows(&block_results[0]);
            log::info!("checking {} active rows", gate_rows.len());
            if !gate_rows.is_empty() || !lookup_rows.is_empty() {
                if let Err(e) =
                    prover.verify_at_rows_par(gate_rows.into_iter(), lookup_rows.into_iter())
                {
                    bail!("{:?}", e);
                }
            }
        } else if let Err(e) = prover.verify_par() {
            bail!("{:?}", e);
        }
        log::info!("mock prove {} done", C::name());
        Ok(())
    }

    pub fn create_target_circuit_proof<C: TargetCircuit>(
        &mut self,
        block_result: &BlockResult,
    ) -> anyhow::Result<TargetCircuitProof, Error> {
        self.create_target_circuit_proof_multi::<C>(&[block_result.clone()])
    }

    pub fn create_target_circuit_proof_multi<C: TargetCircuit>(
        &mut self,
        block_results: &[BlockResult],
    ) -> anyhow::Result<TargetCircuitProof, Error> {
        let (circuit, instance) = C::from_block_results(block_results)?;
        let mut transcript = PoseidonWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

        let instance_slice = instance.iter().map(|x| &x[..]).collect::<Vec<_>>();

        let public_inputs: &[&[&[Fr]]] = &[&instance_slice[..]];

        info!(
            "Create {} proof of block {} ... block {}, batch len {}",
            C::name(),
            block_results[0].block_trace.hash,
            block_results[block_results.len() - 1].block_trace.hash,
            block_results.len()
        );
        if *MOCK_PROVE {
            let prover = MockProver::<Fr>::run(*DEGREE as u32, &circuit, instance.clone())?;
            if let Err(e) = prover.verify_par() {
                bail!("{:?}", e);
            }
            log::info!("mock prove {} done", C::name());
        }

        if !self.target_circuit_pks.contains_key(&C::name()) {
            self.init_pk::<C>();
        }
        let pk = &self.target_circuit_pks[&C::name()];
        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
            &self.params,
            pk,
            &[circuit],
            public_inputs,
            self.rng.clone(),
            &mut transcript,
        )?;
        info!(
            "Create {} proof of block {} ... block {} Successfully!",
            C::name(),
            block_results[0].block_trace.hash,
            block_results[block_results.len() - 1].block_trace.hash,
        );
        let instance_bytes = serialize_instance(&instance);
        Ok(TargetCircuitProof {
            name: C::name(),
            proof: transcript.finalize(),
            instance: instance_bytes,
        })
    }
}
