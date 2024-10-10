use integration::prove::{new_batch_prover, prove_and_verify_bundle};
use prover::{io::from_json_file, utils::init_env_and_log, BatchProof, BundleProvingTask};
//use std::{fs, path::PathBuf};

#[cfg(feature = "prove_verify")]
#[test]
fn test_bundle_prove_verify() {
    use integration::test_util::PARAMS_DIR;
    use itertools::Itertools;
    use prover::config::AGG_DEGREES;

    let output_dir = init_env_and_log("bundle_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let params_map = prover::common::Prover::load_params_map(
        PARAMS_DIR,
        &AGG_DEGREES.iter().copied().collect_vec(),
    );

    let bundle_task = gen_bundle_proving_task(&[
        "tests/test_data/full_proof_batch_agg_1.json",
        "tests/test_data/full_proof_batch_agg_2.json",
    ]);
    // dump_chunk_protocol(&batch, &output_dir);
    let mut batch_prover = new_batch_prover(&params_map, "tests/test_data");
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

#[ignore]
#[test]
fn test_bundle_prove_verify_after_batch() {
    use glob::glob;
    use integration::test_util::PARAMS_DIR;
    use itertools::Itertools;
    use prover::{config::AGG_DEGREES, io::from_json_file, BatchProvingTask};

    let output_dir = init_env_and_log("bundle_tests");

    let mut batch_tasks = glob(&format!("{output_dir}/full_proof_batch_prove_?.json"))
        .unwrap()
        .into_iter()
        .map(|task_path| {
            from_json_file::<BatchProvingTask>(task_path.unwrap().to_str().unwrap()).unwrap()
        })
        .collect::<Vec<_>>();

    batch_tasks
        .as_mut_slice()
        .sort_by_key(|task| task.batch_header.batch_index);

    let batch_proofs: Vec<BatchProof> = batch_tasks
        .iter()
        .map(|task| {
            log::info!("local batch proof {}", task.identifier());
            from_json_file(&format!(
                "{output_dir}/full_proof_batch_{}.json",
                task.identifier()
            ))
            .unwrap()
        })
        .collect();

    let bundle = BundleProvingTask { batch_proofs };
    let params_map = prover::common::Prover::load_params_map(
        PARAMS_DIR,
        &AGG_DEGREES.iter().copied().collect_vec(),
    );

    let mut prover = new_batch_prover(&params_map, &output_dir);
    prove_and_verify_bundle(&output_dir, &mut prover, bundle);
}
