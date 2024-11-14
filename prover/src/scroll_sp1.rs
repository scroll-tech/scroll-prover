use anyhow::Result;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use prover::{
    common, config::LayerId, consts::CHUNK_VK_FILENAME, io::try_to_read, types::ChunkProvingTask,
    zkevm::Verifier, ChunkProof,
    eth_types::l2_types::BlockTrace,
};
use rand::Rng;
use snark_verifier_sdk::Snark;
use std::collections::BTreeMap;

use super::prover_utils::{load_elf, ToSp1BlockTrace};
use sp1_host::SprollRunner;
use sp1_halo2_backend::{Prover as Halo2WrapProver, BaseConfigParams as Halo2WrapParams};


pub struct Sp1Prover<'params> {
    pub prover_impl: common::Prover<'params>,
    pub halo2_wrap_prover: Option<Halo2WrapProver>,
    verifier: Option<Verifier<'params>>,
    raw_vk: Option<Vec<u8>>,
}

impl<'params> Sp1Prover<'params> {
    pub fn from_params_and_assets(
        params_map: &'params BTreeMap<u32, ParamsKZG<Bn256>>,
        assets_dir: &str,
    ) -> Self {
        let prover_impl = common::Prover::from_params_map(params_map);

        let raw_vk = try_to_read(assets_dir, &CHUNK_VK_FILENAME);
        let verifier = if raw_vk.is_none() {
            log::warn!(
                "zkevm-prover: {} doesn't exist in {}",
                *CHUNK_VK_FILENAME,
                assets_dir
            );
            None
        } else {
            Some(Verifier::from_params_and_assets(
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

    pub fn gen_sp1_snark(
        &mut self,
        rng: &mut (impl Rng + Send),
        block_traces: impl IntoIterator<Item = BlockTrace>,
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
        chunk_identifier: Option<&str>,
        inner_id: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<ChunkProof> {
        assert!(!chunk.is_empty());

        let mut runner = SprollRunner::new(chunk.block_traces.into_iter().map(ToSp1BlockTrace))?;

        runner.prepare_stdin();
        #[cfg(feature = "sp1-hint")]
        runner.hook_poseidon()?;
        runner.run_on_host()?;

        log::info!("start prove ");
        unimplemented!();
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
