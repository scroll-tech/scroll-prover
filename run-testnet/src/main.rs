#![allow(dead_code)]
use anyhow::Result;
use ethers_providers::{Http, Provider};
use prover::{
    inner::Prover,
    utils::{read_env_var, GIT_VERSION, short_git_version},
    zkevm::circuit::{
        block_traces_to_witness_block, calculate_row_usage_of_witness_block, SuperCircuit,
        WitnessBlock,
    },
};
use log4rs::{
    append::{
        console::{ConsoleAppender, Target},
        file::FileAppender,
    },
    config::{Appender, Logger, Config, Root},
};
use reqwest::Url;
use serde::Deserialize;
use std::{env, str::FromStr, process::ExitCode};
use types::eth::BlockTrace;

// build common config from enviroment
fn common_log() -> Result<Config> {
    dotenv::dotenv().ok();
    // TODO: cannot support complicated `RUST_LOG` for now.
    let log_level = read_env_var("RUST_LOG", "INFO".to_string());
    let log_level = log::LevelFilter::from_str(&log_level).unwrap_or(log::LevelFilter::Info);

    let stdoutput = ConsoleAppender::builder().target(Target::Stdout).build();

    let config = Config::builder()
    .appenders([
        Appender::builder().build("std", Box::new(stdoutput)),
    ]).build(
        Root::builder()
            .appender("std")
            .build(log_level),
    )?;

    Ok(config)
}

// build config for circuit-debug
fn debug_log(output_dir: &str) -> Result<Config> {
    use std::path::Path;
    let err_output = ConsoleAppender::builder().target(Target::Stderr).build();
    let log_file_path = Path::new(output_dir).join("runner.log");
    let log_file = FileAppender::builder().build(log_file_path).unwrap();
    let config = Config::builder()
    .appenders([
        Appender::builder().build("log-file", Box::new(log_file)),
        Appender::builder().build("stderr", Box::new(err_output)),
    ])
    .logger(
        Logger::builder()
        .appender("log-file")
        .additive(true)
        .build("", log::LevelFilter::Debug)
    )
    .build(
        Root::builder()
            .appender("stderr")
            .build(log::LevelFilter::Warn),
    )?;
    
    Ok(config)
}

fn prepare_chunk_dir(output_dir: &str, chunk_id: u64) -> Result<String> {
    use std::{path::Path, fs};
    let chunk_path = Path::new(output_dir).join(format!("{}", chunk_id));
    fs::create_dir(chunk_path.as_path())?;
    Ok(chunk_path.to_str().ok_or_else(||anyhow::anyhow!("invalid chunk path"))?.into())
}

fn record_chunk_traces(chunk_dir: &str, traces: &[BlockTrace]) -> Result<()>{

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::fs::File;
    use tar::{Header, Builder};
    use std::path::Path;

    let trace_file_path = Path::new(chunk_dir).join("traces.tar.gz");
    let tarfile = File::create(trace_file_path)?;
    let enc = GzEncoder::new(tarfile, Compression::default());
    let mut tar = Builder::new(enc);

    for (i, trace) in traces.iter().enumerate() {
        let trace_str = serde_json::to_string(&trace)?;

        let mut header = Header::new_gnu();
        header.set_path(trace.header.number.map_or_else(
            ||format!("unknown_block_{}.json", i), 
            |blkn|format!("{}.json", blkn), 
        ))?;
        header.set_size(trace_str.len() as u64);
        header.set_cksum();
        tar.append(&header, trace_str.as_bytes())?;
    }

    Ok(())
}

fn chunk_handling(batch_id: i64, chunk_id: i64, block_traces: &[BlockTrace]) -> Result<()>{

    let witness_block = build_block(&block_traces, batch_id, chunk_id)
    .map_err(|e|anyhow::anyhow!("testnet: building block failed {e:?}"))?;

    Prover::<SuperCircuit>::mock_prove_witness_block(&witness_block)
    .map_err(|e|anyhow::anyhow!("testnet: failed to prove chunk {chunk_id} inside batch {batch_id}:\n{e:?}"))?;

    Ok(())
}

const EXIT_NO_MORE_TASK : u8 = 9;
const EXIT_FAILED_ENV : u8 = 13;
const EXIT_FAILED_ENV_WITH_TASK : u8 = 17;

#[tokio::main]
async fn main() -> ExitCode{
    let log_handle = log4rs::init_config(common_log().unwrap()).unwrap();
    log::info!("git version {}", GIT_VERSION);
    log::info!("short git version {}", short_git_version());

    log::info!("relay-alpha testnet runner: begin");

    let setting = Setting::new();
    log::info!("settings: {setting:?}");

    let provider = Provider::<Http>::try_from(&setting.l2geth_api_url)
        .expect("mock-testnet: failed to initialize ethers Provider");

    let (batch_id, chunks) = get_chunks_info(&setting)
        .await
        .unwrap_or_else(|e| {
            panic!("mock-testnet: failed to request API err {e:?}")
        });
    let mut chunks_task_complete = true;
    match chunks {
        None => {
            log::info!("mock-testnet: finished to prove at batch-{batch_id}");
            return ExitCode::from(EXIT_NO_MORE_TASK);
        }
        Some(chunks) => {
            // TODO: restart from last chunk?
            for chunk in chunks {
                let chunk_id = chunk.index;
                log::info!("chunk {:?}", chunk);

                // fetch traces
                let mut block_traces: Vec<BlockTrace> = vec![];
                for block_id in chunk.start_block_number..=chunk.end_block_number {
                    log::info!("mock-testnet: requesting trace of block {block_id}");
 
                    match provider
                        .request(
                            "scroll_getBlockTraceByNumberOrHash",
                            [format!("{block_id:#x}")],
                        )
                        .await 
                    {
                        Ok(trace) => {
                            block_traces.push(trace);
                        }
                        Err(e) => {
                            log::error!("obtain trace from block provider fail: {e:?}");
                            break;
                        }
                    } 
                }

                if block_traces.len() < (chunk.end_block_number - chunk.start_block_number + 1) as usize {
                    chunks_task_complete = false;
                    break;
                }

                // start chunk-level testing
                //let chunk_dir = prepare_chunk_dir(&setting.data_output_dir, chunk_id as u64).unwrap();
                if let Err(_) = prepare_chunk_dir(&setting.data_output_dir, chunk_id as u64)
                    .and_then(|chunk_dir|{
                        record_chunk_traces(&chunk_dir, &block_traces)?;
                        Ok(chunk_dir)
                    })
                    .and_then(|chunk_dir|{
                        log::info!("chunk {} has been recorded to {}", chunk_id, chunk_dir);
                        log_handle.set_config(debug_log(&chunk_dir)?);
                        Ok(())
                    })
                {
                    chunks_task_complete = false;
                    break;                    
                }

                let handling_ret = chunk_handling(batch_id as i64, chunk_id, &block_traces);
                log_handle.set_config(common_log().unwrap());

                if handling_ret.is_err() {
                    // TODO: move data to output dir
                }

                log::info!("chunk {} has been handled", chunk_id);          
            }
        }
    }

    if let Err(e) = notify_chunks_complete(&setting, batch_id as i64, chunks_task_complete).await {
        log::error!("can not deliver complete notify to coordinator: {e:?}");
        return ExitCode::from(EXIT_FAILED_ENV_WITH_TASK);
    }

    if chunks_task_complete {
        log::info!("relay-alpha testnet runner: complete");
        ExitCode::from(0)    
    }else {
        ExitCode::from(EXIT_FAILED_ENV)
    }
}

fn build_block(
    block_traces: &[BlockTrace],
    batch_id: i64,
    chunk_id: i64,
) -> anyhow::Result<WitnessBlock> {
    let gas_total: u64 = block_traces
        .iter()
        .map(|b| b.header.gas_used.as_u64())
        .sum();
    let witness_block = block_traces_to_witness_block(block_traces)?;
    let rows = calculate_row_usage_of_witness_block(&witness_block)?;
    log::info!(
        "rows of batch {batch_id}(block range {:?} to {:?}):",
        block_traces.first().and_then(|b| b.header.number),
        block_traces.last().and_then(|b| b.header.number),
    );
    for r in &rows {
        log::info!("rows of {}: {}", r.name, r.row_num_real);
    }
    let row_num = rows.iter().map(|x| x.row_num_real).max().unwrap();
    log::info!(
        "final rows of chunk {chunk_id}: row {}, gas {}, gas/row {:.2}",
        row_num,
        gas_total,
        gas_total as f64 / row_num as f64
    );
    Ok(witness_block)
}

/// Request chunk info from cordinator 
async fn get_chunks_info(
    setting: &Setting,
) -> Result<(usize, Option<Vec<ChunkInfo>>)> {
    let url = Url::parse(&setting.chunks_url)?;

    let resp: String = reqwest::get(url).await?.text().await?;
    log::debug!("resp is {resp}");
    let resp: RollupscanResponse = serde_json::from_str(&resp)?;
    log::info!(
        "handling batch {}, chunk size {}",
        resp.batch_index,
        resp.chunks.as_ref().unwrap().len()
    );
    Ok((resp.batch_index, resp.chunks))
}

async fn notify_chunks_complete(
    setting: &Setting,
    batch_index: i64,
    completed: bool,
) -> Result<()> {
    let url = Url::parse_with_params(
        &setting.task_url,
        &[(if completed {"done"} else {"drop"}, 
        batch_index.to_string())],
    )?;

    let resp = reqwest::get(url).await?.text().await?;
    log::info!(
        "notify batch {} {}, resp {}",
        batch_index,
        if completed {"done"} else {"drop"},
        resp,
    );
    Ok(())
}

#[derive(Deserialize, Debug)]
struct RollupscanResponse {
    batch_index: usize,
    chunks: Option<Vec<ChunkInfo>>,
}

#[derive(Deserialize, Debug)]
struct ChunkInfo {
    index: i64,
    created_at: String,
    total_tx_num: i64,
    hash: String,
    start_block_number: i64,
    end_block_number: i64,
}

#[derive(Debug, Default)]
struct Setting {
    chunks_url: String,
    task_url: String,
    l2geth_api_url: String,
    data_output_dir: String,
}

impl Setting {
    pub fn new() -> Self {
        let l2geth_api_url =
            env::var("L2GETH_API_URL").expect("run-testnet: Must set env L2GETH_API_URL");
        let coordinator_url = env::var("COORDINATOR_API_URL");
        let (chunks_url, task_url) = if let Ok(url_prefix) = coordinator_url {
            (
                Url::parse(&url_prefix).and_then(|url|url.join("chunks")).expect("run-testnet: Must be valid url for coordinator api"),
                Url::parse(&url_prefix).and_then(|url|url.join("tasks")).expect("run-testnet: Must be valid url for coordinator api"), 
            )
        } else {
            (
                Url::parse(
                    &env::var("CHUNKS_API_URL")
                    .expect("run-test: CHUNKS_API_URL must be set if COORDINATOR_API_URL is not set"),
                ).expect("run-testnet: Must be valid url for chunks api"),
                Url::parse(
                    &env::var("TASKS_API_URL")
                    .expect("run-test: TASKS_API_URL must be set if COORDINATOR_API_URL is not set"),
                ).expect("run-testnet: Must be valid url for tasks api"),    
            )
        };

        let data_output_dir = env::var("OUTPUT_DIR").unwrap_or("output".to_string());

        Self {
            l2geth_api_url,
            data_output_dir,
            chunks_url: chunks_url.as_str().into(),
            task_url: task_url.as_str().into(),
        }
    }
}
