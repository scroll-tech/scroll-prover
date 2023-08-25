#![allow(dead_code)]
use anyhow::Result;
use ethers_providers::{Http, Provider};
use log4rs::{
    append::{
        console::{ConsoleAppender, Target},
        file::FileAppender,
    },
    config::{Appender, Config, Logger, Root},
};
use prover::{
    inner::Prover,
    utils::{read_env_var, short_git_version, GIT_VERSION},
    zkevm::circuit::{
        block_traces_to_witness_block, calculate_row_usage_of_witness_block, SuperCircuit,
        WitnessBlock,
    },
};
use reqwest::Url;
use serde::Deserialize;
use std::{backtrace, env, panic, process::ExitCode, str::FromStr};
use types::eth::BlockTrace;

// build common config from enviroment
fn common_log() -> Result<Config> {
    dotenv::dotenv().ok();
    // TODO: cannot support complicated `RUST_LOG` for now.
    let log_level = read_env_var("RUST_LOG", "INFO".to_string());
    let log_level = log::LevelFilter::from_str(&log_level).unwrap_or(log::LevelFilter::Info);

    let stdoutput = ConsoleAppender::builder().target(Target::Stdout).build();

    let config = Config::builder()
        .appenders([Appender::builder().build("std", Box::new(stdoutput))])
        .build(Root::builder().appender("std").build(log_level))?;

    Ok(config)
}

// build config for circuit-debug
fn debug_log(output_dir: &str) -> Result<Config> {
    use std::path::Path;
    let app_output = ConsoleAppender::builder().target(Target::Stdout).build();
    let log_file_path = Path::new(output_dir).join("runner.log");
    let log_file = FileAppender::builder().build(log_file_path).unwrap();
    let config = Config::builder()
        .appenders([
            Appender::builder().build("log-file", Box::new(log_file)),
            Appender::builder().build("std", Box::new(app_output)),
        ])
        .logger(
            Logger::builder()
                .appender("std")
                .additive(false)
                .build("testnet_runner", log::LevelFilter::Info),
        )
        .build(
            Root::builder()
                .appender("log-file")
                .build(log::LevelFilter::Debug),
        )?;

    Ok(config)
}

fn prepare_chunk_dir(output_dir: &str, chunk_id: u64) -> Result<String> {
    use std::{fs, path::Path};
    let chunk_path = Path::new(output_dir).join(format!("{chunk_id}"));
    fs::create_dir(chunk_path.as_path())?;
    Ok(chunk_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid chunk path"))?
        .into())
}

fn record_chunk_traces(chunk_dir: &str, traces: &[BlockTrace]) -> Result<()> {
    use flate2::{write::GzEncoder, Compression};
    use std::{fs::File, path::Path};
    use tar::{Builder, Header};

    let trace_file_path = Path::new(chunk_dir).join("traces.tar.gz");
    let tarfile = File::create(trace_file_path)?;
    let enc = GzEncoder::new(tarfile, Compression::default());
    let mut tar = Builder::new(enc);

    for (i, trace) in traces.iter().enumerate() {
        let trace_str = serde_json::to_string(&trace)?;

        let mut header = Header::new_gnu();
        header.set_path(trace.header.number.map_or_else(
            || format!("unknown_block_{i}.json"),
            |blkn| format!("{blkn}.json"),
        ))?;
        header.set_mode(0o644);
        header.set_size(trace_str.len() as u64);
        header.set_cksum();
        tar.append(&header, trace_str.as_bytes())?;
    }

    Ok(())
}

fn mark_chunk_failure(chunk_dir: &str, data: &str) -> Result<()> {
    use std::{fs, path::Path};
    fs::write(Path::new(chunk_dir).join("failure"), data)?;
    Ok(())
}

const EXIT_NO_MORE_TASK: u8 = 9;
const EXIT_FAILED_ENV: u8 = 13;
const EXIT_FAILED_ENV_WITH_TASK: u8 = 17;

#[tokio::main]
async fn main() -> ExitCode {
    let log_handle = log4rs::init_config(common_log().unwrap()).unwrap();

    let setting = Setting::new();

    let provider = Provider::<Http>::try_from(&setting.l2geth_api_url)
        .expect("run-testnet: failed to initialize ethers Provider");

    log::info!("git version {}", GIT_VERSION);
    log::info!("short git version {}", short_git_version());
    log::info!("settings: {setting:?}");

    log::info!("relay-alpha testnet runner: begin");

    let (batch_id, chunks) = match get_chunks_info(&setting).await {
        Ok(r) => r,
        Err(e) => {
            log::error!("run-testnet: failed to request API err {e:?}");
            return ExitCode::from(EXIT_FAILED_ENV);
        }
    };

    let mut chunks_task_complete = true;
    match chunks {
        None => {
            log::info!("run-testnet: finished to prove at batch-{batch_id}");
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
                    log::info!("run-testnet: requesting trace of block {block_id}");

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

                if block_traces.len()
                    < (chunk.end_block_number - chunk.start_block_number + 1) as usize
                {
                    chunks_task_complete = false;
                    break;
                }

                // start chunk-level testing
                let chunk_dir = prepare_chunk_dir(&setting.data_output_dir, chunk_id as u64)
                    .and_then(|chunk_dir| {
                        record_chunk_traces(&chunk_dir, &block_traces)?;
                        Ok(chunk_dir)
                    })
                    .and_then(|chunk_dir| {
                        log::info!("chunk {} has been recorded to {}", chunk_id, chunk_dir);
                        log_handle.set_config(debug_log(&chunk_dir)?);
                        Ok(chunk_dir)
                    });
                // u64).unwrap();
                if let Err(e) = chunk_dir {
                    log::error!(
                        "can not prepare output enviroment for chunk {}: {:?}",
                        chunk_id,
                        e
                    );
                    chunks_task_complete = false;
                    break;
                }
                let chunk_dir = chunk_dir.expect("ok ensured");

                let handling_error = std::sync::Arc::new(std::sync::RwLock::new(String::from(
                    "unknown error, message not recorded",
                )));

                let write_error = |handling_error: &std::sync::Arc<std::sync::RwLock<String>>,
                                   err_msg: String| {
                    match handling_error.write() {
                        Ok(mut error_str) => {
                            *error_str = err_msg;
                        }
                        Err(e) => {
                            log::error!(
                                "fail to write error message: {:?}\n backup {}",
                                e,
                                err_msg
                            );
                        }
                    }
                };

                let out_err = handling_error.clone();
                // prepare for running test phase
                panic::set_hook(Box::new(move |panic_info| {
                    write_error(
                        &out_err,
                        format!(
                            "catch test panic: {} \nbacktrace: {}",
                            panic_info,
                            backtrace::Backtrace::capture(),
                        ),
                    );
                }));

                let spec_tasks = setting.spec_tasks.clone();

                let out_err = handling_error.clone();
                let handling_ret = panic::catch_unwind(move || {
                    let witness_block = build_block(&block_traces, batch_id, chunk_id)
                        .map_err(|e| anyhow::anyhow!("testnet: building block failed {e:?}"));

                    if let Err(e) = witness_block {
                        write_error(&out_err, format!("building block fail: {e:?}"));
                        return false;
                    }
                    let witness_block = witness_block.expect("has handled error");

                    // mock
                    if spec_tasks.iter().any(|str| str.as_str() == "mock") {
                        if let Err(e) = Prover::<SuperCircuit>::mock_prove_witness_block(&witness_block)
                        .map_err(|e| {
                            anyhow::anyhow!("testnet: failed to prove chunk {chunk_id} inside batch {batch_id}:\n{e:?}")
                        })
                        {
                            write_error(&out_err, format!("chunk handling fail: {e:?}"));
                            return false;
                        }
                    }

                    // prove
                    if spec_tasks.iter().any(|str| str.as_str() == "mock") {
                        // TODO: add prove code here
                        let prove_ret: Result<()> = Ok(());
                        if let Err(e) = prove_ret {
                            write_error(&out_err, format!("chunk handling fail: {e:?}"));
                            return false;
                        }
                    }
                    true
                });

                let _ = panic::take_hook();

                log_handle.set_config(common_log().unwrap());
                if !handling_ret.unwrap_or(false) {
                    log::debug!("encounter some error in batch {}", batch_id);
                    if let Err(e) = mark_chunk_failure(
                        &chunk_dir,
                        handling_error
                            .read()
                            .map(|reader| reader.clone())
                            .unwrap_or(String::from("default"))
                            .as_str(),
                    ) {
                        log::error!("can not output error data for chunk {}: {:?}", chunk_id, e);
                        chunks_task_complete = false;
                        break;
                    }
                }

                log::info!("chunk {} has been handled", chunk_id);
            }
        }
    }

    if let Err(e) = notify_chunks_complete(&setting, batch_id, chunks_task_complete).await {
        log::error!("can not deliver complete notify to coordinator: {e:?}");
        return ExitCode::from(EXIT_FAILED_ENV_WITH_TASK);
    }

    //TODO: batch level ops

    if chunks_task_complete {
        log::info!("relay-alpha testnet runner: complete");
        ExitCode::from(0)
    } else {
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
async fn get_chunks_info(setting: &Setting) -> Result<(i64, Option<Vec<ChunkInfo>>)> {
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
        &[(
            if completed { "done" } else { "drop" },
            batch_index.to_string(),
        )],
    )?;

    let resp = reqwest::get(url).await?.text().await?;
    log::info!(
        "notify batch {} {}, resp {}",
        batch_index,
        if completed { "done" } else { "drop" },
        resp,
    );
    Ok(())
}

#[derive(Deserialize, Debug)]
struct RollupscanResponse {
    batch_index: i64,
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
    spec_tasks: Vec<String>,
}

impl Setting {
    pub fn new() -> Self {
        let l2geth_api_url =
            env::var("L2GETH_API_URL").expect("run-testnet: Must set env L2GETH_API_URL");
        let coordinator_url = env::var("COORDINATOR_API_URL");
        let (chunks_url, task_url) = if let Ok(url_prefix) = coordinator_url {
            (
                Url::parse(&url_prefix)
                    .and_then(|url| url.join("chunks"))
                    .expect("run-testnet: Must be valid url for coordinator api"),
                Url::parse(&url_prefix)
                    .and_then(|url| url.join("tasks"))
                    .expect("run-testnet: Must be valid url for coordinator api"),
            )
        } else {
            (
                Url::parse(&env::var("CHUNKS_API_URL").expect(
                    "run-test: CHUNKS_API_URL must be set if COORDINATOR_API_URL is not set",
                ))
                .expect("run-testnet: Must be valid url for chunks api"),
                Url::parse(&env::var("TASKS_API_URL").expect(
                    "run-test: TASKS_API_URL must be set if COORDINATOR_API_URL is not set",
                ))
                .expect("run-testnet: Must be valid url for tasks api"),
            )
        };

        let data_output_dir = env::var("OUTPUT_DIR").unwrap_or("output".to_string());

        let spec_tasks_str = env::var("TESTNET_TASKS").unwrap_or_default();
        let spec_tasks = spec_tasks_str.split(',').map(String::from).collect();

        Self {
            l2geth_api_url,
            data_output_dir,
            chunks_url: chunks_url.as_str().into(),
            task_url: task_url.as_str().into(),
            spec_tasks,
        }
    }
}
