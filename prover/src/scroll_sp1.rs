
use prover::{
    common, zkevm::Verifier,
    types::ChunkProvingTask, ChunkProof,
    io::try_to_read,
    config::LayerId,
    consts::CHUNK_VK_FILENAME, 
};
use anyhow::Result;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use std::collections::BTreeMap;
pub struct Sp1Prover<'params> {
    pub prover_impl: common::Prover<'params>,
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
        }
    }

    pub fn get_vk(&self) -> Option<Vec<u8>> {
        self.prover_impl
            .raw_vk(LayerId::Layer2.id())
            .or_else(|| self.raw_vk.clone())
    }

    pub fn gen_chunk_proof(
        &mut self,
        chunk: ChunkProvingTask,
        chunk_identifier: Option<&str>,
        inner_id: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<ChunkProof> {
        assert!(!chunk.is_empty());

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
