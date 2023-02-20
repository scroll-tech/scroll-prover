use std::collections::HashMap;
use std::io::Cursor;
use std::path::PathBuf;

use crate::circuit::{
    block_traces_to_witness_block, check_batch_capacity, SuperCircuit, TargetCircuit, AGG_DEGREE,
    DEGREE,
};
use crate::io::{
    deserialize_fr_matrix, load_instances, serialize_fr_tensor, serialize_instance,
    serialize_verify_circuit_final_pair, serialize_vk, write_verify_circuit_final_pair,
    write_verify_circuit_instance, write_verify_circuit_proof, write_verify_circuit_vk,
};
use crate::utils::load_seed;
use crate::utils::{load_or_create_params, read_env_var};
use anyhow::{bail, Error};
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_pk2, keygen_vk, ProvingKey, VerifyingKey,
};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::poly::kzg::multiopen::ProverGWC;
use halo2_proofs::transcript::{Challenge255, PoseidonWrite};
use halo2_snark_aggregator_api::transcript::sha::ShaWrite;
use halo2_snark_aggregator_circuit::verify_circuit::{
    final_pair_to_instances, Halo2CircuitInstance, Halo2CircuitInstances, Halo2VerifierCircuit,
    Halo2VerifierCircuits, SingleProofWitness,
};
use halo2_snark_aggregator_solidity::MultiCircuitSolidityGenerate;
use log::info;
use once_cell::sync::Lazy;

use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use serde_derive::{Deserialize, Serialize};
use types::base64;
use types::eth::BlockTrace;

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
    #[serde(with = "base64", default)]
    pub vk: Vec<u8>,
    pub proved_block_count: usize,
    pub original_block_count: usize,
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

    pub block_count: usize,
}

pub struct ProvedCircuit {
    pub name: String,
    pub transcript: Vec<u8>,
    pub vk: VerifyingKey<G1Affine>,
    pub instance: Vec<Vec<Vec<Fr>>>,
    pub proved_block_count: usize,
    pub original_block_count: usize,
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
    pub debug_dir: String,
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
            debug_dir: Default::default(),
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

    fn init_pk<C: TargetCircuit>(&mut self, circuit: &<C as TargetCircuit>::Inner) {
        Self::tick(&format!("before init pk of {}", C::name()));
        let pk = keygen_pk2(&self.params, circuit)
            .unwrap_or_else(|e| panic!("failed to generate {} pk: {:?}", C::name(), e));
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
        let rng = XorShiftRng::from_seed(seed);
        Self::from_params_and_rng(params, agg_params, rng)
    }

    pub fn from_fpath(params_fpath: &str, seed_fpath: &str) -> Self {
        let params = load_or_create_params(params_fpath, *DEGREE).expect("failed to init params");
        let agg_params =
            load_or_create_params(params_fpath, *AGG_DEGREE).expect("failed to init params");
        let seed = load_seed(seed_fpath).expect("failed to init rng");
        Self::from_params_and_seed(params, agg_params, seed)
    }

    pub fn debug_load_proved_circuit<C: TargetCircuit>(
        &mut self,
        v: Option<&mut crate::verifier::Verifier>,
    ) -> anyhow::Result<ProvedCircuit> {
        assert!(!self.debug_dir.is_empty());
        log::debug!("debug_load_proved_circuit {}", C::name());
        let file_name = format!("{}/{}_proof.json", self.debug_dir, C::name());
        let file = std::fs::File::open(file_name)?;
        let proof: TargetCircuitProof = serde_json::from_reader(file)?;
        if let Some(v) = v {
            v.verify_target_circuit_proof::<C>(&proof).unwrap();
        }
        self.convert_target_proof::<C>(&proof)
    }

    pub fn prove_circuit<C: TargetCircuit>(
        &mut self,
        block_traces: &[BlockTrace],
    ) -> anyhow::Result<ProvedCircuit> {
        let proof = self.create_target_circuit_proof_batch::<C>(block_traces)?;
        self.convert_target_proof::<C>(&proof)
    }

    fn convert_target_proof<C: TargetCircuit>(
        &mut self,
        proof: &TargetCircuitProof,
    ) -> anyhow::Result<ProvedCircuit> {
        let instances: Vec<Vec<Vec<u8>>> = serde_json::from_reader(&proof.instance[..])?;
        let instances = deserialize_fr_matrix(instances);
        //debug_assert!(instances.is_empty(), "instance not supported yet");
        let vk = match self.target_circuit_pks.get(&proof.name) {
            Some(pk) => pk.get_vk().clone(),
            None => {
                let allow_read_vk = false;
                if allow_read_vk && !proof.vk.is_empty() {
                    VerifyingKey::<G1Affine>::read::<_, C::Inner, Bn256, _>(
                        &mut Cursor::new(&proof.vk),
                        &self.params,
                    )
                    .unwrap()
                } else {
                    keygen_vk(&self.params, &C::empty()).unwrap()
                }
            }
        };
        if *OPT_MEM {
            Self::tick(&format!("before release pk of {}", C::name()));
            self.target_circuit_pks.remove(&C::name());
            Self::tick(&format!("after release pk of {}", &C::name()));
        }

        Ok(ProvedCircuit {
            name: proof.name.clone(),
            transcript: proof.proof.clone(),
            vk,
            instance: vec![instances],
            proved_block_count: proof.proved_block_count,
            original_block_count: proof.original_block_count,
        })
    }

    pub fn create_solidity_verifier(&self, proof: &AggCircuitProof) -> String {
        MultiCircuitSolidityGenerate {
            verify_vk: self.agg_pk.as_ref().expect("pk should be inited").get_vk(),
            verify_params: &self.agg_params,
            verify_circuit_instance: load_instances(&proof.instance),
            proof: proof.proof.clone(),
            verify_public_inputs_size: 4, // not used now
        }
        .call("".into())
    }

    pub fn create_agg_circuit_proof(
        &mut self,
        block_trace: &BlockTrace,
    ) -> anyhow::Result<AggCircuitProof> {
        self.create_agg_circuit_proof_batch(&[block_trace.clone()])
    }

    pub fn create_agg_circuit_proof_batch(
        &mut self,
        block_traces: &[BlockTrace],
    ) -> anyhow::Result<AggCircuitProof> {
        let circuit_results: Vec<ProvedCircuit> =
            vec![self.prove_circuit::<SuperCircuit>(block_traces)?];
        self.create_agg_circuit_proof_impl(circuit_results)
    }

    pub fn create_agg_circuit_proof_impl(
        &mut self,
        circuit_results: Vec<ProvedCircuit>,
    ) -> anyhow::Result<AggCircuitProof> {
        ///////////////////////////// build verifier circuit from block result ///////////////////
        let target_circuits = [0];
        let verifier_params = self.params.verifier_params();
        let verify_circuit = Halo2VerifierCircuits::<'_, Bn256, 1> {
            circuits: target_circuits.map(|i| {
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
            coherent: Vec::new(),
        };
        ///////////////////////////// build verifier circuit from block result done ///////////////////
        let n_instances = target_circuits.map(|i| vec![circuit_results[i].instance.clone()]);
        log::debug!("n_instances {:?}", n_instances);
        let n_transcript = target_circuits.map(|i| vec![circuit_results[i].transcript.clone()]);
        let instances: [Halo2CircuitInstance<'_, Bn256>; 1] =
            target_circuits.map(|i| Halo2CircuitInstance {
                name: circuit_results[i].name.clone(),
                params: verifier_params,
                vk: &circuit_results[i].vk,
                n_instances: &n_instances[i],
                n_transcript: &n_transcript[i],
            });
        let verify_circuit_final_pair =
            Halo2CircuitInstances::<'_, Bn256, 1>(instances).calc_verify_circuit_final_pair();
        log::debug!("final pair {:?}", verify_circuit_final_pair);
        let verify_circuit_instances =
            final_pair_to_instances::<_, Bn256>(&verify_circuit_final_pair);

        if self.agg_pk.is_none() {
            log::info!("generate agg pk: begin");
            let verify_circuit_vk =
                keygen_vk(&self.agg_params, &verify_circuit).expect("keygen_vk should not fail");
            log::info!("generate agg pk: vk done");
            let verify_circuit_pk = keygen_pk(&self.agg_params, verify_circuit_vk, &verify_circuit)
                .expect("keygen_pk should not fail");
            self.agg_pk = Some(verify_circuit_pk);
            log::info!("init_agg_pk: done");
        } else {
            log::info!("generate agg pk: done");
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
            if let Err(errs) = prover.verify_par() {
                log::error!("err num: {}", errs.len());
                for err in &errs {
                    log::error!("{}", err);
                }
                bail!("{:#?}", errs);
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
        log::info!(
            "create agg proof done, block proved {}/{}",
            circuit_results[0].proved_block_count,
            circuit_results[0].original_block_count
        );

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
            block_count: circuit_results[0].proved_block_count,
        })
    }

    pub fn mock_prove_target_circuit<C: TargetCircuit>(
        block_trace: &BlockTrace,
        full: bool,
    ) -> anyhow::Result<()> {
        Self::mock_prove_target_circuit_batch::<C>(&[block_trace.clone()], full)
    }

    pub fn mock_prove_target_circuit_batch<C: TargetCircuit>(
        block_traces: &[BlockTrace],
        full: bool,
    ) -> anyhow::Result<()> {
        log::info!(
            "start mock prove {}, rows needed {}",
            C::name(),
            C::estimate_rows(block_traces)
        );
        let original_block_len = block_traces.len();
        let mut block_traces = block_traces.to_vec();
        check_batch_capacity(&mut block_traces)?;
        let witness_block = block_traces_to_witness_block(&block_traces)?;
        let (circuit, instance) = C::from_witness_block(&witness_block)?;
        let prover = MockProver::<Fr>::run(*DEGREE as u32, &circuit, instance)?;
        if !full {
            // FIXME for packing
            let (gate_rows, lookup_rows) = C::get_active_rows(&block_traces);
            log::info!("checking {} active rows", gate_rows.len());
            if !gate_rows.is_empty() || !lookup_rows.is_empty() {
                if let Err(e) =
                    prover.verify_at_rows_par(gate_rows.into_iter(), lookup_rows.into_iter())
                {
                    bail!("{:?}", e);
                }
            }
        } else if let Err(errs) = prover.verify_par() {
            log::error!("err num: {}", errs.len());
            for err in &errs {
                log::error!("{}", err);
            }
            bail!("{:#?}", errs);
        }
        log::info!(
            "mock prove {} done. block proved {}/{}",
            C::name(),
            block_traces.len(),
            original_block_len
        );
        Ok(())
    }

    pub fn create_target_circuit_proof<C: TargetCircuit>(
        &mut self,
        block_trace: &BlockTrace,
    ) -> anyhow::Result<TargetCircuitProof, Error> {
        self.create_target_circuit_proof_batch::<C>(&[block_trace.clone()])
    }

    pub fn create_target_circuit_proof_batch<C: TargetCircuit>(
        &mut self,
        block_traces: &[BlockTrace],
    ) -> anyhow::Result<TargetCircuitProof, Error> {
        let original_block_count = block_traces.len();
        let mut block_traces = block_traces.to_vec();
        check_batch_capacity(&mut block_traces)?;
        let witness_block = block_traces_to_witness_block(&block_traces)?;
        let (circuit, instance) = C::from_witness_block(&witness_block)?;
        let mut transcript = PoseidonWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

        let instance_slice = instance.iter().map(|x| &x[..]).collect::<Vec<_>>();

        let public_inputs: &[&[&[Fr]]] = &[&instance_slice[..]];

        info!(
            "Create {} proof of block {} ... block {}, batch len {}",
            C::name(),
            block_traces[0].header.hash.unwrap(),
            block_traces[block_traces.len() - 1].header.hash.unwrap(),
            block_traces.len()
        );
        if *MOCK_PROVE {
            log::info!("mock prove {} start", C::name());
            let prover = MockProver::<Fr>::run(*DEGREE as u32, &circuit, instance.clone())?;
            if let Err(errs) = prover.verify_par() {
                log::error!("err num: {}", errs.len());
                for err in &errs {
                    log::error!("{}", err);
                }
                bail!("{:#?}", errs);
            }
            log::info!("mock prove {} done", C::name());
        }

        if !self.target_circuit_pks.contains_key(&C::name()) {
            //self.init_pk::<C>(&circuit);
            self.init_pk::<C>(&C::empty());
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
            block_traces[0].header.hash.unwrap(),
            block_traces[block_traces.len() - 1].header.hash.unwrap(),
        );
        let instance_bytes = serialize_instance(&instance);
        let proof = transcript.finalize();
        let name = C::name();
        log::debug!(
            "{} circuit: proof {:?}, instance len {}",
            name,
            &proof[0..15],
            instance_bytes.len()
        );
        let target_proof = TargetCircuitProof {
            name: name.clone(),
            proof,
            instance: instance_bytes,
            vk: serialize_vk(pk.get_vk()),
            original_block_count,
            proved_block_count: witness_block.context.ctxs.len(),
        };
        if !self.debug_dir.is_empty() {
            // write vk
            let mut fd = std::fs::File::create(format!("{}/{}.vk", self.debug_dir, &name)).unwrap();
            pk.get_vk().write(&mut fd).unwrap();
            drop(fd);

            // write proof
            //let mut folder = PathBuf::from_str(&self.debug_dir).unwrap();
            //write_file(&mut folder, &format!("{}.proof", name), &proof);
            let output_file = format!("{}/{}_proof.json", self.debug_dir, name);
            let mut fd = std::fs::File::create(output_file).unwrap();
            serde_json::to_writer_pretty(&mut fd, &target_proof).unwrap();
        }
        Ok(target_proof)
    }
}
