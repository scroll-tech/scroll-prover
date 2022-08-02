use std::collections::HashMap;
use std::path::PathBuf;

use crate::circuit::{
    EvmCircuit, PoseidonCircuit, StateCircuit, TargetCircuit, ZktrieCircuit, AGG_DEGREE, DEGREE,
};
use crate::io::{
    deserialize_fr_matrix, serialize_commitments, serialize_fr_tensor, serialize_instance,
    serialize_vk, write_verify_circuit_instance, write_verify_circuit_instance_commitments_be,
    write_verify_circuit_proof, write_verify_circuit_proof_be, write_verify_circuit_vk,
};
use crate::utils::load_seed;
use crate::utils::{load_or_create_params, read_env_var};
use anyhow::{bail, Error};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pairing::bn256::{Fr, G1Affine};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, ProvingKey};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Challenge255, PoseidonWrite};
use halo2_snark_aggregator_api::transcript::sha::ShaWrite;
use halo2_snark_aggregator_circuit::verify_circuit::{
    calc_verify_circuit_instances, verify_circuit_builder, Halo2VerifierCircuit, ProvedCircuit,
};
use log::info;
use once_cell::sync::Lazy;
use pairing::bn256::Bn256;
use pairing::group::Curve;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use serde_derive::{Deserialize, Serialize};
use types::base64;
use types::eth::{mock_block_result, BlockResult};

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
    // FIXME: tech debt
    #[serde(with = "base64")]
    pub proof_rust: Vec<u8>,

    #[serde(with = "base64")]
    pub proof_solidity: Vec<u8>,

    #[serde(with = "base64")]
    pub instance: Vec<u8>,

    #[serde(with = "base64")]
    pub instance_commitments: Vec<u8>,

    #[serde(with = "base64")]
    pub vk: Vec<u8>,
}

impl AggCircuitProof {
    pub fn write_to_dir(&self, out_dir: &mut PathBuf) {
        write_verify_circuit_instance_commitments_be(out_dir, &self.instance_commitments);
        write_verify_circuit_instance(out_dir, &self.instance);
        write_verify_circuit_proof(out_dir, &self.proof_rust);
        write_verify_circuit_proof_be(out_dir, &self.proof_solidity);
        write_verify_circuit_vk(out_dir, &self.vk);

        out_dir.push("full_proof.data");
        let mut fd = std::fs::File::create(out_dir.as_path()).unwrap();
        out_dir.pop();
        serde_json::to_writer_pretty(&mut fd, &self).unwrap()
    }
}
pub struct Prover {
    pub params: Params<G1Affine>,
    pub agg_params: Params<G1Affine>,
    pub rng: XorShiftRng,

    pub target_circuit_pks: HashMap<String, ProvingKey<G1Affine>>,
    pub agg_pk: Option<ProvingKey<G1Affine>>,
    //pub target_circuit_vks: HashMap<String, ProvingKey<G1Affine>>,
}

impl Prover {
    pub fn new(params: Params<G1Affine>, agg_params: Params<G1Affine>, rng: XorShiftRng) -> Self {
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

    fn init_agg_pk_from_verifier_circuit(
        &mut self,
        verify_circuit: &Halo2VerifierCircuit<'_, Bn256>,
    ) {
        let verify_circuit_vk =
            keygen_vk(&self.agg_params, verify_circuit).expect("keygen_vk should not fail");

        let verify_circuit_pk = keygen_pk(&self.agg_params, verify_circuit_vk, verify_circuit)
            .expect("keygen_pk should not fail");
        self.agg_pk = Some(verify_circuit_pk);
    }

    pub fn from_params_and_rng(
        params: Params<G1Affine>,
        agg_params: Params<G1Affine>,
        rng: XorShiftRng,
    ) -> Self {
        Self::new(params, agg_params, rng)
    }

    pub fn from_params_and_seed(
        params: Params<G1Affine>,
        agg_params: Params<G1Affine>,
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
        Self::from_params_and_rng(params, agg_params, rng)
    }

    fn prove_circuit<C: TargetCircuit>(
        &mut self,
        block_result: &BlockResult,
    ) -> anyhow::Result<ProvedCircuit<G1Affine, Bn256>> {
        let proof = self.create_target_circuit_proof::<C>(block_result)?;

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

    pub fn init_agg_pk(&mut self) -> anyhow::Result<()> {
        if self.agg_pk.is_some() {
            log::warn!("agg_pk is not none, skip re-init");
            return Ok(());
        }
        log::info!("init_agg_pk: creating target circuit results...");
        let block_result: &BlockResult = &mock_block_result();

        // TODO: reuse code with `create_agg_circuit_proof`. Lifetime puzzles..
        let circuit_results: Vec<ProvedCircuit<_, _>> = vec![
            self.prove_circuit::<EvmCircuit>(block_result)?,
            self.prove_circuit::<StateCircuit>(block_result)?,
            self.prove_circuit::<PoseidonCircuit>(block_result)?,
            self.prove_circuit::<ZktrieCircuit>(block_result)?,
        ];
        let target_circuit_public_input_len = circuit_results
            .iter()
            .map(|c| c.instance[0].iter().map(|col| col.len()).max().unwrap_or(0))
            .max()
            .unwrap_or(0);
        let target_circuit_params_verifier = self
            .params
            .verifier::<Bn256>(target_circuit_public_input_len)?;

        let _verify_circuit_instances =
            calc_verify_circuit_instances(&target_circuit_params_verifier, &circuit_results);

        // first advice col of evm circuit == first advice col of state circuit
        // they are a same RLCed rw table col
        let coherent = vec![[(0, 0), (1, 0)]];
        let verify_circuit: Halo2VerifierCircuit<'_, Bn256> =
            verify_circuit_builder(&target_circuit_params_verifier, &circuit_results, coherent);

        log::info!("init_agg_pk: init from verifier circuit");
        self.init_agg_pk_from_verifier_circuit(&verify_circuit);
        log::info!("init_agg_pk: init done");
        Ok(())
    }

    pub fn create_agg_circuit_proof(
        &mut self,
        block_result: &BlockResult,
    ) -> anyhow::Result<AggCircuitProof> {
        let circuit_results: Vec<ProvedCircuit<_, _>> = vec![
            self.prove_circuit::<EvmCircuit>(block_result)?,
            self.prove_circuit::<StateCircuit>(block_result)?,
            self.prove_circuit::<PoseidonCircuit>(block_result)?,
            self.prove_circuit::<ZktrieCircuit>(block_result)?,
        ];
        let target_circuit_public_input_len = circuit_results
            .iter()
            .map(|c| c.instance[0].iter().map(|col| col.len()).max().unwrap_or(0))
            .max()
            .unwrap_or(0);
        let target_circuit_params_verifier = self
            .params
            .verifier::<Bn256>(target_circuit_public_input_len)?;

        let verify_circuit_instances =
            calc_verify_circuit_instances(&target_circuit_params_verifier, &circuit_results);

        // first advice col of evm circuit == first advice col of state circuit
        // they are a same RLCed rw table col
        let coherent = vec![[(0, 0), (1, 0)]];
        let verify_circuit: Halo2VerifierCircuit<'_, Bn256> =
            verify_circuit_builder(&target_circuit_params_verifier, &circuit_results, coherent);

        if self.agg_pk.is_none() {
            self.init_agg_pk_from_verifier_circuit(&verify_circuit);
        } else {
            log::info!("using existing agg_pk");
        }

        let instances_slice: &[&[&[Fr]]] = &[&[&verify_circuit_instances[..]]];
        let mut transcript = ShaWrite::<_, _, Challenge255<_>>::init(vec![], vec![]);

        log::info!("create agg proof");
        create_proof(
            &self.agg_params,
            self.agg_pk.as_ref().unwrap(),
            &[verify_circuit],
            instances_slice,
            self.rng.clone(),
            &mut transcript,
        )?;
        log::info!("create agg proof done");

        let (proof, proof_be) = transcript.finalize();

        let instance_commitments: Vec<u8> = {
            let limbs = 4;
            let verify_circuit_params_verifier =
                self.agg_params.verifier::<Bn256>(limbs * 4).unwrap();
            let instances: &[&[&[_]]] = &[&[&verify_circuit_instances]];
            let instance_commitments: Vec<Vec<G1Affine>> = instances
                .iter()
                .map(|instance| {
                    instance
                        .iter()
                        .map(|instance| {
                            verify_circuit_params_verifier
                                .commit_lagrange(instance.to_vec())
                                .to_affine()
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            serialize_commitments(&instance_commitments)
        };

        let instances_for_serde = serialize_fr_tensor(&[vec![verify_circuit_instances]]);
        let instance_bytes = serde_json::to_vec(&instances_for_serde)?;
        let vk_bytes = serialize_vk(self.agg_pk.as_ref().expect("pk should be inited").get_vk());
        Ok(AggCircuitProof {
            proof_rust: proof,
            proof_solidity: proof_be,
            instance: instance_bytes,
            instance_commitments,
            vk: vk_bytes,
        })
    }

    pub fn mock_prove_target_circuit<C: TargetCircuit>(
        block_result: &BlockResult,
        full: bool,
    ) -> anyhow::Result<()> {
        log::info!("start mock prove {}", C::name());
        let (circuit, instance) = C::from_block_result(block_result)?;
        let prover = MockProver::<Fr>::run(*DEGREE as u32, &circuit, instance)?;
        if !full {
            let (gate_rows, lookup_rows) = C::get_active_rows(block_result);
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
        let (circuit, instance) = C::from_block_result(block_result)?;
        let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);

        let instance_slice = instance.iter().map(|x| &x[..]).collect::<Vec<_>>();

        let public_inputs: &[&[&[Fr]]] = &[&instance_slice[..]];

        info!(
            "Create {} proof of block {}",
            C::name(),
            block_result.block_trace.hash
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
        create_proof(
            &self.params,
            pk,
            &[circuit],
            public_inputs,
            self.rng.clone(),
            &mut transcript,
        )?;
        info!(
            "Create {} proof of block {} Successfully!",
            C::name(),
            block_result.block_trace.hash
        );
        let instance_bytes = serialize_instance(&instance);
        Ok(TargetCircuitProof {
            name: C::name(),
            proof: transcript.finalize(),
            instance: instance_bytes,
        })
    }
}
