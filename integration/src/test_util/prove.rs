use super::PARAMS_DIR;
use prover::{
    aggregator::{Prover, Verifier},
    common,
    config::LayerId,
    BatchProvingTask, CompressionCircuit, EvmProof, Snark,
};
use std::env;

/// The `output_dir` is assumed to output_dir of chunk proving.
pub fn new_batch_prover(output_dir: &str) -> Prover {
    env::set_var("CHUNK_PROTOCOL_FILENAME", "chunk_chunk_0.protocol");
    let prover = Prover::from_dirs(PARAMS_DIR, output_dir);
    log::info!("Constructed batch prover");

    prover
}

pub fn prove_and_verify_batch(
    output_dir: &str,
    batch_prover: &mut Prover,
    batch: BatchProvingTask,
) {
    let chunk_num = batch.chunk_proofs.len();
    log::info!("Prove batch BEGIN: chunk_num = {chunk_num}");

    let batch_proof = batch_prover
        .gen_agg_evm_proof(batch, None, Some(output_dir))
        .unwrap();

    env::set_var("AGG_VK_FILENAME", "vk_batch_agg.vkey");
    let verifier = Verifier::from_dirs(PARAMS_DIR, output_dir);
    log::info!("Constructed aggregator verifier");

    assert!(verifier.verify_agg_evm_proof(batch_proof));
    log::info!("Verified batch proof");

    log::info!("Prove batch END: chunk_num = {chunk_num}");
}

pub fn gen_and_verify_normal_and_evm_proofs(
    prover: &mut common::Prover,
    layer_id: LayerId,
    previous_snark: Snark,
    output_dir: Option<&str>,
) -> (Snark, EvmProof) {
    let normal_proof = gen_normal_proof(prover, layer_id, previous_snark.clone(), output_dir);
    let evm_proof = gen_evm_proof(prover, layer_id, previous_snark, output_dir);
    verify_normal_and_evm_proofs(
        prover,
        layer_id,
        normal_proof.clone(),
        &evm_proof,
        output_dir,
    );

    (normal_proof, evm_proof)
}

pub fn gen_and_verify_normal_proof(
    prover: &mut common::Prover,
    layer_id: LayerId,
    previous_snark: Snark,
) -> (bool, Snark) {
    let normal_proof = gen_normal_proof(prover, layer_id, previous_snark, None);
    let verified = verify_normal_proof(prover, layer_id, normal_proof.clone());

    (verified, normal_proof)
}

fn gen_evm_proof(
    prover: &mut common::Prover,
    layer_id: LayerId,
    previous_snark: Snark,
    output_dir: Option<&str>,
) -> EvmProof {
    let id = layer_id.id();
    let degree = layer_id.degree();

    // Load or generate compression EVM proof.
    let evm_proof = prover
        .load_or_gen_comp_evm_proof("evm", id, true, degree, previous_snark, output_dir)
        .unwrap();
    log::info!("Generated EVM proof: {id}");

    evm_proof
}

fn gen_normal_proof(
    prover: &mut common::Prover,
    layer_id: LayerId,
    previous_snark: Snark,
    output_dir: Option<&str>,
) -> Snark {
    let id = layer_id.id();
    let degree = layer_id.degree();

    // Load or generate compression snark.
    let snark = prover
        .load_or_gen_comp_snark("normal", id, true, degree, previous_snark, output_dir)
        .unwrap();
    log::info!("Generated compression snark: {id}");

    snark
}

fn verify_normal_and_evm_proofs(
    prover: &mut common::Prover,
    layer_id: LayerId,
    normal_proof: Snark,
    evm_proof: &EvmProof,
    output_dir: Option<&str>,
) {
    let id = layer_id.id();
    let degree = layer_id.degree();
    let config_path = layer_id.config_path();

    env::set_var("COMPRESSION_CONFIG", config_path);
    let vk = evm_proof.proof.vk::<CompressionCircuit>();

    let params = prover.params(degree).clone();
    let verifier = common::Verifier::<CompressionCircuit>::new(params, vk);
    log::info!("Constructed common verifier");

    assert!(verifier.verify_snark(normal_proof));
    log::info!("Verified normal proof: {id}");

    verifier.evm_verify(evm_proof, output_dir);
    log::info!("Verified EVM proof: {id}");
}

fn verify_normal_proof(
    prover: &mut common::Prover,
    layer_id: LayerId,
    normal_proof: Snark,
) -> bool {
    let id = layer_id.id();
    let degree = layer_id.degree();
    let config_path = layer_id.config_path();
    env::set_var("COMPRESSION_CONFIG", config_path);

    let pk = prover.pk(id).unwrap();
    let vk = pk.get_vk().clone();

    let params = prover.params(degree).clone();
    let verifier = common::Verifier::<CompressionCircuit>::new(params, vk);
    log::info!("Constructed common verifier");

    let verified = verifier.verify_snark(normal_proof);
    log::info!("Verified normal proof: {verified}");

    verified
}
