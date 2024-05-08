use integration::test_util::{
    gen_and_verify_batch_proofs, load_batch, load_block_traces_for_test, PARAMS_DIR,
};
use prover::{
    aggregator::Prover,
    config::LayerId,
    proof::from_json_file,
    utils::{chunk_trace_to_witness_block, init_env_and_log},
    BatchHash, BatchProof, ChunkHash, ChunkProof, CompressionCircuit,
};
use serde_derive::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf};

//#[cfg(feature = "prove_verify")]
#[test]
fn test_batch_prove_verify() {
    let output_dir = init_env_and_log("batch_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    /////// Step1: load batch proving task and build prover ///////////////////////////////
    // let batch_task = "tests/test_data/full_proof_1.json";
    let batch_task = "tests/test_data/batch_task_69776.json";
    let assets_dir = "assets";
    let chunk_hashes_proofs = load_batch_proving_task(batch_task, &output_dir);

    env::set_var("AGG_VK_FILENAME", "agg_vk.vkey");
    env::set_var("CHUNK_PROTOCOL_FILENAME", "chunk.protocol");
    let mut batch_prover = Prover::from_dirs(PARAMS_DIR, assets_dir);
    log::info!("Constructed batch prover");

    let chunk_num = chunk_hashes_proofs.len();
    log::info!("Prove batch BEGIN: chunk_num = {chunk_num}");

    //////// Step2: prove layer3 /////////////////////////////////////////////////////////
    // Load or generate aggregation snark (layer-3).
    let layer3_snark = batch_prover
        .load_or_gen_last_agg_snark("agg", chunk_hashes_proofs, Some(&output_dir))
        .unwrap();

    /////// Step3.1: prove layer4 circuit with poseidon transcript ///////////////////////
    let layer_id = LayerId::Layer4;
    let id = layer_id.id();
    let degree = layer_id.degree();
    let params = batch_prover.inner.params(degree).clone();
    let config_path = layer_id.config_path();
    env::set_var("COMPRESSION_CONFIG", config_path);

    // Load or generate compression snark.
    let normal_proof = batch_prover
        .inner
        .load_or_gen_comp_snark(
            "normal",
            id,
            true,
            degree,
            layer3_snark.clone(),
            Some(&output_dir),
        )
        .unwrap();
    log::info!("Generated compression snark: {id}");
    // Note: whether you use posedion transcript or keccak transcript, the circuit is same
    // So vk is same.
    let vk = batch_prover
        .inner
        .pk(id)
        .map(|pk| pk.get_vk())
        .unwrap()
        .clone();

    let verifier = prover::common::Verifier::<CompressionCircuit>::new(params, vk);
    log::info!("Constructed common verifier");

    assert!(verifier.verify_snark(normal_proof));
    log::info!("Verified normal proof: {id}");

    /////// Step3.2: prove layer4 circuit with keccak transcript ///////////////////////
    let test_evm_proof = false;
    if test_evm_proof {
        let evm_proof = batch_prover
            .inner
            .load_or_gen_comp_evm_proof("evm", id, true, degree, layer3_snark, Some(&output_dir))
            .unwrap();
        log::info!("Generated EVM proof: {id}");

        // `evm_verify` can also dump evm verifier yul/bin to disk
        verifier.evm_verify(&evm_proof, Some(&output_dir));
        log::info!("Verified EVM proof: {id}");

        let batch_proof = BatchProof::from(evm_proof.proof);
        batch_proof.dump(&output_dir, "agg").unwrap();
        batch_proof.clone().assert_calldata();

        // The `Verifier` used in FFI
        let verifier = prover::aggregator::Verifier::from_dirs(PARAMS_DIR, assets_dir);
        log::info!("Constructed aggregator verifier");

        assert!(verifier.verify_agg_evm_proof(batch_proof));
        log::info!("Verified batch proof");
    }

    log::info!("Prove batch END: chunk_num = {chunk_num}");
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchTaskDetail {
    chunk_infos: Vec<ChunkHash>,
    chunk_proofs: Vec<ChunkProof>,
}

fn load_batch_proving_task(filename: &str, output_dir: &str) -> Vec<(ChunkHash, ChunkProof)> {
    let batch_task_detail: BatchTaskDetail = from_json_file(filename).unwrap();
    let chunk_hashes = batch_task_detail.chunk_infos;
    let chunk_proofs = batch_task_detail.chunk_proofs;

    let chunk_hashes_proofs: Vec<_> = chunk_hashes[..]
        .iter()
        .cloned()
        .zip(chunk_proofs[..].iter().cloned())
        .collect();

    let dump_protocol = false;
    if dump_protocol {
        log::info!("dumping first chunk protocol to {output_dir}/chunk_protocol");
        let chunk_protocol = &chunk_hashes_proofs.first().unwrap().1.protocol;
        // Dump chunk-procotol for further batch-proving.
        prover::proof::dump_data(output_dir, "chunk.protocol", &chunk_protocol);
    }

    log::info!(
        "Loaded chunk-hashes and chunk-proofs: total = {}",
        chunk_hashes_proofs.len()
    );
    chunk_hashes_proofs
}

#[test]
fn test_batch_pi_consistency() {
    let output_dir = init_env_and_log("batch_pi");
    log::info!("Initialized ENV and created output-dir {output_dir}");
    let trace_paths = load_batch().unwrap();

    let max_num_snarks = 15;
    let chunk_traces: Vec<_> = trace_paths
        .iter()
        .map(|trace_path| {
            env::set_var("TRACE_PATH", trace_path);
            load_block_traces_for_test().1
        })
        .collect();

    let mut chunk_hashes: Vec<ChunkHash> = chunk_traces
        .into_iter()
        .enumerate()
        .map(|(_i, chunk_trace)| {
            let witness_block = chunk_trace_to_witness_block(chunk_trace.clone()).unwrap();
            ChunkHash::from_witness_block(&witness_block, false)
        })
        .collect();

    let real_chunk_count = chunk_hashes.len();
    if real_chunk_count < max_num_snarks {
        let mut padding_chunk_hash = chunk_hashes.last().unwrap().clone();
        padding_chunk_hash.is_padding = true;

        // Extend to MAX_AGG_SNARKS for both chunk hashes and layer-2 snarks.
        chunk_hashes
            .extend(std::iter::repeat(padding_chunk_hash).take(max_num_snarks - real_chunk_count));
    }

    let batch_hash = BatchHash::construct(&chunk_hashes);
    let blob = batch_hash.blob_assignments();

    let challenge = blob.challenge;
    let evaluation = blob.evaluation;
    println!("blob.challenge: {challenge:x}");
    println!("blob.evaluation: {evaluation:x}");
    for (i, elem) in blob.coefficients.iter().enumerate() {
        println!("blob.coeffs[{}]: {elem:x}", i);
    }
}
