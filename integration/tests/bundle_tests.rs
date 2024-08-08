use integration::prove::{new_batch_prover, prove_and_verify_bundle};
use prover::{io::from_json_file, utils::init_env_and_log, BatchProof, BundleProvingTask};
//use std::{fs, path::PathBuf};

#[cfg(feature = "prove_verify")]
#[test]
fn test_bundle_prove_verify() {
    let output_dir = init_env_and_log("bundle_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let bundle_task = gen_bundle_proving_task(&[
        "tests/test_data/full_proof_batch_agg_1.json",
        "tests/test_data/full_proof_batch_agg_2.json",
    ]);
    // dump_chunk_protocol(&batch, &output_dir);
    let mut batch_prover = new_batch_prover("tests/test_data");
    prove_and_verify_bundle(&output_dir, &mut batch_prover, bundle_task);
}

fn gen_bundle_proving_task(batch_proof_files: &[&str]) -> BundleProvingTask {
    let mut batch_proofs = Vec::new();

    for proof_file in batch_proof_files {
        let batch_proof: BatchProof = from_json_file(proof_file).unwrap();
        log::debug!("Loaded batch-proofs, header {:#?}", batch_proof.batch_hash,);
        batch_proofs.push(batch_proof);
    }

    BundleProvingTask { batch_proofs }
}
