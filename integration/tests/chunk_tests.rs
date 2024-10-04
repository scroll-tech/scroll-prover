use integration::test_util::{ASSETS_DIR, PARAMS_DIR};
use prover::utils::init_env_and_log;

#[cfg(feature = "prove_verify")]
#[test]
fn test_chunk_prove_verify() {
    use integration::{
        prove::prove_and_verify_chunk,
        test_util::{load_chunk, trace_path_for_test},
    };
    use itertools::Itertools;
    use prover::{config::ZKEVM_DEGREES, ChunkProvingTask};

    let output_dir = init_env_and_log("chunk_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let params_map = prover::common::Prover::load_params_map(
        PARAMS_DIR,
        &ZKEVM_DEGREES.iter().copied().collect_vec(),
    );

    let trace_path = trace_path_for_test();
    let traces = load_chunk(&trace_path).1;
    let chunk = ChunkProvingTask::from(traces);
    prove_and_verify_chunk(chunk, None, &params_map, ASSETS_DIR, &output_dir);
}

#[cfg(feature = "prove_verify")]
#[test]
fn test_sp1_chunk_prove_verify() {
    use integration::{
        test_util::{load_chunk, trace_path_for_test},
    };
    use itertools::Itertools;
    use prover::{config::{ZKEVM_DEGREES, LayerId::Layer2}, ChunkProvingTask};
    use prover::{common::Prover, utils::chunk_trace_to_witness_block, io::load_snark};
    use std::{fs, path::Path};
    use snark_verifier_sdk::verify_snark_shplonk;

    let output_dir = init_env_and_log("chunk_tests");
    log::info!("Initialized ENV and created output-dir {output_dir}");

    let trace_path = trace_path_for_test();
    let trace_asset_path = Path::new(&trace_path);
    let trace_asset_path = if trace_asset_path.is_dir() {
        trace_asset_path.to_path_buf()
    } else {
        trace_asset_path.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new(".").to_path_buf())
    };

    let traces = load_chunk(&trace_path).1;
    let chunk = ChunkProvingTask::from(traces);
    let task_id = chunk.identifier();

    // TODO: verify sp1 snark with given vk?

    // must copy sp1 snark as compress snark, match the naming with the code in 'load_or_gen_comp_snark'
    let inner_snark_name = format!("sp1_snark_{}.json", task_id);
    // fs::copy(
    //     &trace_asset_path.join(&inner_snark_name),
    //     &Path::new(&output_dir).join(&inner_snark_name),
    // ).unwrap();

    let sp1_snark = load_snark(trace_asset_path.join(&inner_snark_name).to_str().unwrap()).ok().flatten().unwrap();

    //let witness_block = chunk_trace_to_witness_block(chunk.block_traces).unwrap();
    let params_map = prover::common::Prover::load_params_map(
        PARAMS_DIR,
        &ZKEVM_DEGREES.iter().copied().collect_vec(),
    );    
    
    let mut comm_prover = Prover::from_params_map(&params_map);

    let snark = comm_prover.load_or_gen_comp_snark(
        // layer1
        "sp1",
        Layer2.id(),
        false,
        Layer2.degree(),
        sp1_snark,
        Some(&output_dir),
    ).unwrap();

}
