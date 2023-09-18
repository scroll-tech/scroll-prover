use anyhow::Result;
use ethers_providers::{Http, Provider};
use integration::test_util::{prepare_circuit_capacity_checker, run_circuit_capacity_checker};
#[cfg(any(feature = "inner-prove", feature = "chunk-prove"))]
use once_cell::sync::Lazy;
#[cfg(any(feature = "inner-prove", not(feature = "chunk-prove")))]
use prover::zkevm::circuit;
#[cfg(any(feature = "inner-prove", feature = "chunk-prove"))]
use prover::{
    common::{Prover, Verifier},
    config::LayerId,
    config::{INNER_DEGREE, ZKEVM_DEGREES},
    utils::read_env_var,
};
use prover::{
    utils::init_env_and_log, zkevm::circuit::block_traces_to_witness_block, BlockTrace,
    WitnessBlock,
};
use reqwest::Url;
use serde::Deserialize;
use std::{
    env,
    panic::{self, AssertUnwindSafe},
};

const DEFAULT_BEGIN_BATCH: i64 = 1;
const DEFAULT_END_BATCH: i64 = i64::MAX;

#[cfg(any(feature = "inner-prove", feature = "chunk-prove"))]
static mut REAL_PROVER: Lazy<Prover> = Lazy::new(|| {
    let params_dir = read_env_var("SCROLL_PROVER_PARAMS_DIR", "./test_params".to_string());

    let degrees: Vec<u32> = if cfg!(feature = "inner-prove") {
        vec![*INNER_DEGREE]
    } else {
        // for chunk-prove
        (*ZKEVM_DEGREES).clone()
    };

    let prover = Prover::from_params_dir(&params_dir, &degrees);
    log::info!("Constructed real-prover");

    prover
});

#[cfg(feature = "inner-prove")]
static mut INNER_VERIFIER: Lazy<
    Verifier<<circuit::SuperCircuit as circuit::TargetCircuit>::Inner>,
> = Lazy::new(|| {
    let prover = unsafe { &mut REAL_PROVER };
    let params = prover.params(*INNER_DEGREE).clone();

    let pk = prover
        .pk(LayerId::Inner.id())
        .expect("Failed to get inner-prove PK");
    let vk = pk.get_vk().clone();

    let verifier = Verifier::new(params, vk);
    log::info!("Constructed inner-verifier");

    verifier
});

#[cfg(feature = "chunk-prove")]
static mut CHUNK_VERIFIER: Lazy<Verifier<prover::CompressionCircuit>> = Lazy::new(|| {
    env::set_var("COMPRESSION_CONFIG", LayerId::Layer2.config_path());

    let prover = unsafe { &mut REAL_PROVER };
    let params = prover.params(LayerId::Layer2.degree()).clone();

    let pk = prover
        .pk(LayerId::Layer2.id())
        .expect("Failed to get chunk-prove PK");
    let vk = pk.get_vk().clone();

    let verifier = Verifier::new(params, vk);
    log::info!("Constructed chunk-verifier");

    verifier
});

#[tokio::main]
async fn main() {
    init_env_and_log("mock_testnet");

    log::info!("mock-testnet: begin");

    let setting = Setting::new();
    log::info!("mock-testnet: {setting:?}");

    prepare_circuit_capacity_checker();
    log::info!("mock-testnet: prepared ccc");

    let provider = Provider::<Http>::try_from(&setting.l2geth_api_url)
        .expect("mock-testnet: failed to initialize ethers Provider");

    for batch_id in setting.begin_batch..=setting.end_batch {
        log::info!("mock-testnet: requesting block traces of batch {batch_id}");

        let chunks = get_traces_by_block_api(&setting, batch_id).await;

        let chunks = chunks.unwrap_or_else(|e| {
            panic!("mock-testnet: failed to request API with batch-{batch_id}, err {e:?}")
        });

        match chunks {
            None => {
                log::info!("mock-testnet: finished to prove at batch-{batch_id}");
                break;
            }
            Some(chunks) => {
                for chunk in chunks {
                    let chunk_id = chunk.index;
                    log::info!("mock-testnet: handling chunk {:?}", chunk_id);

                    // fetch traces
                    let mut block_traces: Vec<BlockTrace> = vec![];
                    for block_id in chunk.start_block_number..=chunk.end_block_number {
                        log::info!("mock-testnet: requesting trace of block {block_id}");

                        let trace = provider
                            .request(
                                "scroll_getBlockTraceByNumberOrHash",
                                [format!("{block_id:#x}")],
                            )
                            .await
                            .unwrap();
                        block_traces.push(trace);
                    }

                    let witness_block = match build_block(&block_traces, batch_id, chunk_id) {
                        Ok(block) => block,
                        Err(e) => {
                            log::error!("mock-testnet: building block failed {e:?}");
                            continue;
                        }
                    };
                    if env::var("CIRCUIT").unwrap_or_default() == "ccc" {
                        continue;
                    }

                    let result = panic::catch_unwind(AssertUnwindSafe(|| {
                        let test_id = format!("batch-{batch_id}-chunk-{chunk_id}");
                        #[cfg(feature = "inner-prove")]
                        inner_prove(&test_id, &witness_block);
                        #[cfg(feature = "chunk-prove")]
                        chunk_prove(&test_id, &witness_block);
                        #[cfg(not(any(feature = "inner-prove", feature = "chunk-prove")))]
                        mock_prove(&test_id, &witness_block);
                    }));

                    match result {
                        Ok(_) => {
                            log::info!(
                                "mock-testnet: succeeded to prove chunk {chunk_id} inside batch {batch_id}"
                            )
                        }
                        Err(err) => {
                            let panic_err = if let Some(s) = err.downcast_ref::<String>() {
                                s.to_string()
                            } else if let Some(s) = err.downcast_ref::<&str>() {
                                s.to_string()
                            } else {
                                format!("unable to get panic info {err:?}")
                            };
                            log::error!(
                                "mock-testnet: failed to prove chunk {chunk_id} inside batch {batch_id}:\n{panic_err:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    log::info!("mock-testnet: end");
}

fn build_block(
    block_traces: &[BlockTrace],
    batch_id: i64,
    chunk_id: i64,
) -> anyhow::Result<WitnessBlock> {
    let witness_block = block_traces_to_witness_block(block_traces)?;
    run_circuit_capacity_checker(batch_id, chunk_id, block_traces, &witness_block);
    Ok(witness_block)
}

/// Request block traces by first using rollup API to get chunk info, then fetching blocks from
/// l2geth. Return None if no more batches.
async fn get_traces_by_block_api(
    setting: &Setting,
    batch_index: i64,
) -> Result<Option<Vec<ChunkInfo>>> {
    let url = Url::parse_with_params(
        &setting.rollupscan_api_url,
        &[("batch_index", batch_index.to_string())],
    )?;

    let resp: String = reqwest::get(url).await?.text().await?;
    log::debug!("resp is {resp}");
    let resp: RollupscanResponse = serde_json::from_str(&resp)?;
    log::info!(
        "handling batch {}, chunk size {}",
        resp.batch_index,
        resp.chunks.as_ref().unwrap().len()
    );
    Ok(resp.chunks)
}

#[derive(Deserialize, Debug)]
struct RollupscanResponse {
    batch_index: usize,
    chunks: Option<Vec<ChunkInfo>>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct ChunkInfo {
    index: i64,
    created_at: String,
    total_tx_num: i64,
    hash: String,
    start_block_number: i64,
    end_block_number: i64,
}

#[derive(Debug)]
struct Setting {
    begin_batch: i64,
    end_batch: i64,
    l2geth_api_url: String,
    rollupscan_api_url: String,
}

impl Setting {
    pub fn new() -> Self {
        let l2geth_api_url =
            env::var("L2GETH_API_URL").expect("mock-testnet: Must set env L2GETH_API_URL");
        let rollupscan_api_url = env::var("ROLLUPSCAN_API_URL");
        let rollupscan_api_url =
            rollupscan_api_url.unwrap_or_else(|_| "http://10.0.3.119:8560/api/chunks".to_string());
        let begin_batch = env::var("PROVE_BEGIN_BATCH")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(DEFAULT_BEGIN_BATCH);
        let end_batch = env::var("PROVE_END_BATCH")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(DEFAULT_END_BATCH);

        Self {
            begin_batch,
            end_batch,
            l2geth_api_url,
            rollupscan_api_url,
        }
    }
}

#[cfg(not(any(feature = "inner-prove", feature = "chunk-prove")))]
fn mock_prove(test_id: &str, witness_block: &WitnessBlock) {
    log::info!("{test_id}: mock-prove BEGIN");

    prover::inner::Prover::<circuit::SuperCircuit>::mock_prove_witness_block(witness_block)
        .unwrap_or_else(|err| panic!("{test_id}: failed to mock-prove: {err}"));

    log::info!("{test_id}: mock-prove END");
}

#[cfg(feature = "inner-prove")]
fn inner_prove(test_id: &str, witness_block: &WitnessBlock) {
    log::info!("{test_id}: inner-prove BEGIN");

    let prover = unsafe { &mut REAL_PROVER };

    let rng = prover::utils::gen_rng();
    let snark = prover
        .gen_inner_snark::<circuit::SuperCircuit>(LayerId::Inner.id(), rng, witness_block)
        .unwrap_or_else(|err| panic!("{test_id}: failed to generate inner snark: {err}"));
    log::info!("{test_id}: generated inner snark");

    let verifier = unsafe { &mut INNER_VERIFIER };

    let verified = verifier.verify_snark(snark);
    assert!(verified, "{test_id}: failed to verify inner snark");

    log::info!("{test_id}: inner-prove END");
}

#[cfg(feature = "chunk-prove")]
fn chunk_prove(test_id: &str, witness_block: &WitnessBlock) {
    log::info!("{test_id}: chunk-prove BEGIN");

    let prover = unsafe { &mut REAL_PROVER };

    let snark = prover
        .load_or_gen_final_chunk_snark(test_id, witness_block, None, None)
        .unwrap_or_else(|err| panic!("{test_id}: failed to generate chunk snark: {err}"));
    log::info!("{test_id}: generated chunk snark");

    let verifier = unsafe { &mut CHUNK_VERIFIER };
    let verified = verifier.verify_snark(snark);
    assert!(verified, "{test_id}: failed to verify chunk snark");

    log::info!("{test_id}: chunk-prove END");
}
