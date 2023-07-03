//! Initialization and utility APIs for Prover.

use super::Prover;
use crate::{
    config::{CHUNK_DEGREE, INNER_DEGREE},
    utils::{downsize_params, load_params, DEFAULT_SERDE_FORMAT},
};
use halo2_proofs::{
    halo2curves::bn256::Bn256,
    poly::{
        commitment::{Params, ParamsProver},
        kzg::commitment::{ParamsKZG, ParamsVerifierKZG},
    },
};

impl Prover {
    /// Memory usage tracker.
    pub(crate) fn tick(desc: &str) {
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

    pub fn from_params(agg_params: ParamsKZG<Bn256>) -> Self {
        assert!(agg_params.k() == *CHUNK_DEGREE);
        let mut params = agg_params.clone();
        downsize_params(&mut params, *INNER_DEGREE);

        // notice that k < k_agg which is not necessary the case in practice
        log::info!(
            "loaded parameters for degrees {} and {}",
            *INNER_DEGREE,
            *CHUNK_DEGREE
        );

        // this check can be skipped since the `params` is downsized?
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

        Self::new(params, agg_params)
    }

    pub fn from_params_dir(params_dir: &str) -> Self {
        let agg_params = load_params(params_dir, *CHUNK_DEGREE, DEFAULT_SERDE_FORMAT)
            .expect("Failed to load params");
        Self::from_params(agg_params)
    }
}
