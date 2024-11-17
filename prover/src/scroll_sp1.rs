use anyhow::Result;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use prover::{
    Prover as ProverImpl, LayerId, CHUNK_VK_FILENAME, try_read, ChunkProvingTask,
    ChunkVerifier, 
    eth_types::l2_types::BlockTrace,
    ChunkInfo, chunk_trace_to_witness_block,
    ChunkProofV2Metadata, ChunkProofV2,
};
use rand::Rng;
use snark_verifier_sdk::Snark;
use std::{path::PathBuf, collections::BTreeMap};

use super::prover_utils::{load_elf, ToSp1BlockTrace};
use sp1_host::SprollRunner;
use sp1_halo2_backend::{Prover as Halo2WrapProver, BaseConfigParams as Halo2WrapParams};


pub struct Sp1Prover<'params> {
    pub prover_impl: ProverImpl<'params>,
    pub halo2_wrap_prover: Option<Halo2WrapProver>,
    verifier: Option<ChunkVerifier<'params>>,
    raw_vk: Option<Vec<u8>>,
}

impl<'params> Sp1Prover<'params> {
    pub fn from_params_and_assets(
        params_map: &'params BTreeMap<u32, ParamsKZG<Bn256>>,
        assets_dir: &str,
    ) -> Self {
        let path = PathBuf::from(assets_dir).join(CHUNK_VK_FILENAME.clone());
        let raw_vk = try_read(&path);

        let prover_impl = ProverImpl::from_params_map(params_map);

        let verifier = if raw_vk.is_none() {
            log::warn!(
                "Sp1Prover setup without verifying key (dev mode): {} doesn't exist in {}",
                *CHUNK_VK_FILENAME,
                assets_dir
            );
            None
        } else {
            Some(ChunkVerifier::from_params_and_assets(
                prover_impl.params_map,
                assets_dir,
            ))
        };
        Self {
            prover_impl,
            raw_vk,
            verifier,
            halo2_wrap_prover: None,
        }
    }

    pub fn get_vk(&self) -> Option<Vec<u8>> {
        self.prover_impl
            .raw_vk(LayerId::Layer2.id())
            .or_else(|| self.raw_vk.clone())
    }

    pub fn gen_sp1_snark<'a>(
        &mut self,
        rng: impl Rng + Send,
        block_traces: impl IntoIterator<Item = &'a BlockTrace>,
    ) -> Result<Snark> {
        let mut runner = SprollRunner::new(block_traces.into_iter().map(ToSp1BlockTrace))?;

        runner.prepare_stdin();
        #[cfg(feature = "sp1-hint")]
        runner.hook_poseidon()?;
        runner.run_on_host()?;

        log::info!("start sp1 prove");
        let sp1_client = SprollRunner::prove_client();
        let (sp1_proof, vk) = runner.prove_compressed(&sp1_client, &load_elf()?, true)?;

        log::info!("start halo2 wrap");
        if self.halo2_wrap_prover.is_none() {
            let param = Halo2WrapParams::load();
            let wrap_prover = if let Some(param) = param {
                Halo2WrapProver::new(param, None)
            } else {
                Halo2WrapProver::new_test(LayerId::Layer1.degree() as usize)
            };
            self.halo2_wrap_prover.replace(wrap_prover);
        }
        let wrap_prover = self.halo2_wrap_prover.as_mut().expect("has been created");
        let preprocessed_proof = wrap_prover.preprocess(
            sp1_client.prover.sp1_prover(), // TODO: do not downgrade to cpu prover?
            &vk, 
            sp1_proof
        )?;
        if wrap_prover.config().test_only {
            log::warn!("no param set, test circuit");
            wrap_prover.test_param(&preprocessed_proof)?;
        }

        let snark = wrap_prover.prove(
            Some(self.prover_impl.params(wrap_prover.config().k as u32)), 
            rng, 
            &preprocessed_proof,
        )?;
        Ok(snark)
    }

    pub fn gen_chunk_proof(
        &mut self,
        chunk: ChunkProvingTask,
        chunk_id: Option<&str>,
        _inner_id: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<ChunkProofV2> {
        assert!(!chunk.is_empty());
        use prover::gen_rng;

        let sp1_snark = self.gen_sp1_snark(
            gen_rng(),
            &chunk.block_traces
        )?;

        let chunk_identifier = chunk_id.map_or_else(|| chunk.identifier(), |name| name.to_string());
        let witness_block = chunk_trace_to_witness_block(chunk.block_traces)?;
        let chunk_info = if let Some(chunk_info_input) = chunk.chunk_info {
            chunk_info_input
        } else {
            log::info!("gen chunk_info {chunk_identifier:?}");
            ChunkInfo::from_witness_block(&witness_block, false)
        };

        let comp_snark = self.prover_impl.load_or_gen_comp_snark(
            &chunk_identifier,
            LayerId::Layer2.id(),
            false,
            LayerId::Layer2.degree(),
            sp1_snark,
            output_dir,
        )?;

        let pk = self.prover_impl.pk(LayerId::Layer2.id());
        let proof_metadata =
            ChunkProofV2Metadata::new(&comp_snark, prover::ChunkKind::Sp1, chunk_info, None)?;
        let proof = ChunkProofV2::new(comp_snark, pk, proof_metadata)?;

        // in case we read the snark directly from previous calculation,
        // the pk is not avaliable and we skip dumping the proof
        if pk.is_some() {
            if let Some(output_dir) = output_dir {
                proof.dump(output_dir, &chunk_identifier)?;
            }
        } else {
            log::info!("skip dumping vk since snark is restore from disk")
        }

        Ok(proof)
    }

    /// Check vk generated is same with vk loaded from assets
    fn check_vk(&self) {
        if self.raw_vk.is_some() {
            let gen_vk = self
                .prover_impl
                .raw_vk(LayerId::Layer2.id())
                .unwrap_or_default();
            if gen_vk.is_empty() {
                log::warn!("no gen_vk found, skip check_vk");
                return;
            }
            let init_vk = self.raw_vk.clone().unwrap_or_default();
            if gen_vk != init_vk {
                log::error!(
                    "sp1-prover: generated VK is different with init one - gen_vk = {:?}, init_vk = {:?}",
                    gen_vk.get(..16), init_vk.get(..16),
                );
            }
        }
    }
}
