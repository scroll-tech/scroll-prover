use integration::prove::{new_batch_prover, prove_and_verify_batch};
use prover::{io::from_json_file, utils::init_env_and_log, BatchProvingTask};
use std::{fs, path::PathBuf};

#[cfg(feature = "prove_verify")]
#[test]
fn test_batch_prove_verify() {
    let output_dir = init_env_and_log("batch_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let batch = load_batch_proving_task("tests/test_data/full_proof_1.json");
    dump_chunk_protocol(&batch, &output_dir);
    let mut batch_prover = new_batch_prover(&output_dir);
    prove_and_verify_batch(&output_dir, &mut batch_prover, batch);
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_batches_with_each_chunk_num_prove_verify() {
    let output_dir = init_env_and_log("batches_with_each_chunk_num_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let batch = load_batch_proving_task("tests/test_data/full_proof_1.json");
    dump_chunk_protocol(&batch, &output_dir);
    let mut batch_prover = new_batch_prover(&output_dir);

    // Iterate over chunk proofs to test with 1 to max chunks (in a batch).
    for len in 1..batch.chunk_proofs.len() {
        let mut output_dir = PathBuf::from(&output_dir);
        output_dir.push(format!("batch_{}", len));
        fs::create_dir_all(&output_dir).unwrap();
        let batch = BatchProvingTask {
            chunk_proofs: batch.chunk_proofs[..len].to_vec(),
            batch_header: batch.batch_header,
        };
        prove_and_verify_batch(&output_dir.to_string_lossy(), &mut batch_prover, batch);
    }
}

fn load_batch_proving_task(batch_task_file: &str) -> BatchProvingTask {
    let batch: BatchProvingTask = from_json_file(batch_task_file).unwrap();
    let tx_bytes_total_len: usize = batch
        .chunk_proofs
        .iter()
        .map(|c| c.chunk_info.tx_bytes.len())
        .sum();
    log::info!("Loaded chunk-hashes and chunk-proofs, batch info: chunk num {}, tx_bytes_total_len {tx_bytes_total_len}", batch.chunk_proofs.len());
    batch
}

fn dump_chunk_protocol(batch: &BatchProvingTask, output_dir: &str) {
    // Dump chunk-procotol to "chunk_chunk_0.protocol" for batch proving.
    batch
        .chunk_proofs
        .first()
        .unwrap()
        .dump(output_dir, "0")
        .unwrap();
}
