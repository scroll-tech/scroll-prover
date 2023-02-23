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
use crate::utils::{load_or_create_params, read_env_var};
use crate::utils::{load_seed, metric_of_witness_block};
use anyhow::{bail, Error};
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_pk2, keygen_vk, ProvingKey, VerifyingKey,
};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverGWC, ProverSHPLONK};
use halo2_proofs::transcript::{Challenge255, PoseidonWrite};
use halo2_proofs::SerdeFormat;
use halo2_snark_aggregator_api::transcript::sha::ShaWrite;
use halo2_snark_aggregator_circuit::verify_circuit::{
    final_pair_to_instances, Halo2CircuitInstance, Halo2CircuitInstances, Halo2VerifierCircuit,
    Halo2VerifierCircuits, SingleProofWitness,
};
use halo2_snark_aggregator_solidity::MultiCircuitSolidityGenerate;
use log::info;
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use serde_derive::{Deserialize, Serialize};
use snark_verifier::system::halo2::{compile, Config};
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::halo2::{
    gen_proof_shplonk, gen_snark_gwc, PoseidonTranscript, POSEIDON_SPEC,
};
use snark_verifier_sdk::{gen_pk, NativeLoader, Snark};
use types::base64;
use types::eth::BlockTrace;

#[cfg(target_os = "linux")]
extern crate procfs;

pub static OPT_MEM: Lazy<bool> = Lazy::new(|| read_env_var("OPT_MEM", false));
pub static MOCK_PROVE: Lazy<bool> = Lazy::new(|| read_env_var("MOCK_PROVE", false));

/// A serialized proof that is to be aggregated.
#[derive(Deserialize, Serialize, Debug)]
pub struct InnerCircuitProof {
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

/// The final, serialized, aggregated proof that is to be verified on chain.
#[derive(Deserialize, Serialize, Debug, Default)]
pub struct OuterCircuitProof {
    #[serde(with = "base64")]
    pub proof: Vec<u8>,

    #[serde(with = "base64")]
    pub instance: Vec<u8>,

    #[serde(with = "base64")]
    pub vk: Vec<u8>,

    pub block_count: usize,
}

impl OuterCircuitProof {
    pub fn write_to_dir(&self, out_dir: &mut PathBuf) {
        write_verify_circuit_instance(out_dir, &self.instance);
        write_verify_circuit_proof(out_dir, &self.proof);
        write_verify_circuit_vk(out_dir, &self.vk);

        out_dir.push("full_proof.data");
        let mut fd = std::fs::File::create(out_dir.as_path()).unwrap();
        out_dir.pop();
        serde_json::to_writer_pretty(&mut fd, &self).unwrap()
    }
}

/// The prover that takes `InnerCircuitProof` and generate the final `OuterCircuitProof`.
#[derive(Debug)]
pub struct OuterCircuitProver {
    pub params: ParamsKZG<Bn256>,
    pub agg_params: ParamsKZG<Bn256>,
    pub rng: XorShiftRng,

    pub target_circuit_pks: HashMap<String, ProvingKey<G1Affine>>,
    pub agg_pk: Option<ProvingKey<G1Affine>>,
    pub debug_dir: String,
}

impl OuterCircuitProver {
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
        // Question(Zhenfei): why check consistency here instead of in new()?
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

    /// Load the cached proof. Should only be used for debugging purpose.
    pub fn debug_load_inner_circuit<C: TargetCircuit>(
        &mut self,
        v: Option<&mut crate::verifier::Verifier>,
    ) -> anyhow::Result<(Snark, usize)> {
        assert!(!self.debug_dir.is_empty());
        log::debug!("debug_load_outer_circuit {}", C::name());
        let file_name = format!("{}/{}_proof.json", self.debug_dir, C::name());
        let file = std::fs::File::open(file_name)?;
        let proof: InnerCircuitProof = serde_json::from_reader(file)?;
        if let Some(v) = v {
            v.verify_target_circuit_proof::<C>(&proof).unwrap();
        }
        self.convert_target_proof::<C>(&proof)
    }

    pub fn build_inner_circuit<C: TargetCircuit>(
        &mut self,
        block_traces: &[BlockTrace],
    ) -> anyhow::Result<(Snark, usize)> {
        let proof = self.create_target_circuit_proof_batch::<C>(block_traces)?;
        self.convert_target_proof::<C>(&proof)
    }

    /// Extract an `InnerCircuit` from a InnerCircuitProof; update self's target_circuit pk list.
    // Does not perform any real computation.
    fn convert_target_proof<C: TargetCircuit>(
        &mut self,
        proof: &InnerCircuitProof,
    ) -> anyhow::Result<(Snark, usize)> {
        let instances: Vec<Vec<Vec<u8>>> = serde_json::from_reader(&proof.instance[..])?;
        let instances = deserialize_fr_matrix(instances);
        let num_instance: Vec<usize> = instances.iter().map(|x| x.len()).collect();

        let vk = match self.target_circuit_pks.get(&proof.name) {
            Some(pk) => pk.get_vk().clone(),
            None => {
                let allow_read_vk = false;
                if allow_read_vk && !proof.vk.is_empty() {
                    VerifyingKey::<G1Affine>::read::<_, C::Inner>(
                        &mut Cursor::new(&proof.vk),
                        SerdeFormat::Processed,
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

        let protocol = compile(
            &self.params,
            &vk,
            Config::kzg().with_num_instance(num_instance.clone()),
        );
        let snark = Snark::new(protocol, instances.clone(), proof.proof.clone());

        Ok((snark, proof.original_block_count))
    }

    /// TODO: Fix this function
    // pub fn create_solidity_verifier(&self, proof: &OuterCircuitProof) -> String {
    //     let res =
    //     MultiCircuitSolidityGenerate {
    //         verify_vk: self.agg_pk.as_ref().expect("pk should be inited").get_vk(),
    //         verify_params: &self.agg_params,
    //         verify_circuit_instance: load_instances(&proof.instance),
    //         proof: proof.proof.clone(),
    //         verify_public_inputs_size: 4, // not used now
    //     }
    //     .call("".into());
    //     println!("create solidity verifier: {}", res);
    //     res
    // }

    pub fn create_agg_circuit_proof(
        &mut self,
        block_trace: &BlockTrace,
    ) -> anyhow::Result<OuterCircuitProof> {
        self.create_agg_circuit_proof_batch(&[block_trace.clone()])
    }

    /// Input a list of BlockTrace, build the in
    pub fn create_agg_circuit_proof_batch(
        &mut self,
        block_traces: &[BlockTrace],
    ) -> anyhow::Result<OuterCircuitProof> {
        let (snark, first_proved_block_count) =
            self.build_inner_circuit::<SuperCircuit>(block_traces)?;

        self.create_agg_circuit_proof_impl(vec![snark], first_proved_block_count)
    }

    /// Input a list of inner circuit and their proofs,
    /// generate an aggregated proof
    pub fn create_agg_circuit_proof_impl(
        &mut self,
        snarks: Vec<Snark>,
        first_proved_block_count: usize,
    ) -> anyhow::Result<OuterCircuitProof> {
        ///////////////////////////// build verifier circuit from block result ///////////////////
        let verifier_params = self.params.verifier_params();
        let mut rng = OsRng;
        let agg_circuit = AggregationCircuit::new(&verifier_params, snarks, rng);

        ///////////////////////////// build verifier circuit from block result done ///////////////////
        let instances = vec![agg_circuit.instance()];
        let pk = gen_pk(&verifier_params, &agg_circuit, None);
        let proof = gen_proof_shplonk(
            verifier_params,
            &pk,
            agg_circuit.clone(),
            instances.clone(),
            &mut rng,
            None,
        );

        let instances_for_serde = serialize_fr_tensor(&[instances]);
        let instance_bytes = serde_json::to_vec(&instances_for_serde)?;
        let vk_bytes = serialize_vk(self.agg_pk.as_ref().expect("pk should be inited").get_vk());

        Ok(OuterCircuitProof {
            proof,
            instance: instance_bytes,
            vk: vk_bytes,
            block_count: first_proved_block_count,
        })
    }

    pub fn mock_prove_inner_circuit<C: TargetCircuit>(
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
        log::info!(
            "mock proving batch of len {}, batch metric {:?}",
            original_block_len,
            metric_of_witness_block(&witness_block)
        );
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
            "mock prove {} done. block proved {}/{}, batch metric: {:?}",
            C::name(),
            block_traces.len(),
            original_block_len,
            metric_of_witness_block(&witness_block),
        );
        Ok(())
    }

    pub fn create_target_circuit_proof<C: TargetCircuit>(
        &mut self,
        block_trace: &BlockTrace,
    ) -> anyhow::Result<InnerCircuitProof, Error> {
        self.create_target_circuit_proof_batch::<C>(&[block_trace.clone()])
    }

    pub fn create_target_circuit_proof_batch<C: TargetCircuit>(
        &mut self,
        block_traces: &[BlockTrace],
    ) -> anyhow::Result<InnerCircuitProof, Error> {
        let original_block_count = block_traces.len();
        let mut block_traces = block_traces.to_vec();
        check_batch_capacity(&mut block_traces)?;
        let witness_block = block_traces_to_witness_block(&block_traces)?;
        log::info!(
            "proving batch of len {}, batch metric {:?}",
            original_block_count,
            metric_of_witness_block(&witness_block)
        );
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
        create_proof::<KZGCommitmentScheme<_>, ProverSHPLONK<_>, _, _, _, _>(
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
        let target_proof = InnerCircuitProof {
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
            pk.get_vk().write(&mut fd, SerdeFormat::Processed).unwrap();
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
