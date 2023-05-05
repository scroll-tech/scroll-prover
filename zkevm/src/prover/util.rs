//! Initialization and utility APIs for Prover.
//!
use super::Prover;
use crate::circuit::{TargetCircuit, AGG_DEGREE, DEGREE};
use crate::utils::load_or_create_params;
use crate::utils::load_seed;
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::plonk::keygen_pk2;
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{ParamsKZG, ParamsVerifierKZG};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;

impl Prover {
    /// Build a new Prover from parameters.
    pub fn new(params: ParamsKZG<Bn256>, agg_params: ParamsKZG<Bn256>, rng: XorShiftRng) -> Self {
        Self {
            params,
            agg_params,
            rng,
            target_circuit_pks: Default::default(),
            agg_pk: None,
        }
    }

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

    /// Initiates the public key for a given inner circuit.
    pub(crate) fn init_pk<C: TargetCircuit>(&mut self, circuit: &<C as TargetCircuit>::Inner) {
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
        Self::from_params_and_seed(params, agg_params, seed)
    }
}
