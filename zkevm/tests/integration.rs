use halo2_proofs::plonk::{ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use pairing::bn256::G1Affine;
use rand_xorshift::XorShiftRng;
use zkevm::keygen::{gen_evm_pk, gen_evm_vk, gen_state_pk, gen_state_vk};
use zkevm::prover::Prover;
use zkevm::utils::{load_or_create_params, load_or_create_rng};
use zkevm::verifier::Verifier;

const PARAMS_FPATH: &str = "./test_params";
const SEED_FPATH: &str = "./test_seed";

static PARAMS: Params<G1Affine> = load_or_create_params(PARAMS_FPATH).unwrap();
static RNG: XorShiftRng = load_or_create_rng(SEED_FPATH).unwrap();

static EVM_VK: VerifyingKey<G1Affine> = gen_evm_vk(&PARAMS).unwrap();
static EVM_PK: ProvingKey<G1Affine> = gen_evm_pk(&PARAMS).unwrap();
static STATE_VK: VerifyingKey<G1Affine> = gen_state_vk(&PARAMS).unwrap();
static STATE_PK: ProvingKey<G1Affine> = gen_state_pk(&PARAMS).unwrap();

// #[cfg(feature = "prove_verify")]
#[test]
fn test_prove_verify() {
    // let prover = Prover::new(PARAMS, &EVM_PK, &STATE_PK, &RNG);
}
