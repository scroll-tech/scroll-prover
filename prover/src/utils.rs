use anyhow::Result;
use chrono::Utc;
use git_version::git_version;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::halo2curves::FieldExt;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::SerdeFormat;
use log::LevelFilter;
use log4rs::append::console::{ConsoleAppender, Target};
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use rand::rngs::OsRng;
use std::fs::{self, metadata, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Once;
use types::eth::{BlockTrace, BlockTraceJsonRpcResult};
use zkevm_circuits::witness;

pub const DEFAULT_SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytesUnchecked;

pub const GIT_VERSION: &str = git_version!();

pub static LOGGER: Once = Once::new();

fn param_path_for_degree(params_dir: &str, degree: usize) -> String {
    //format!("{params_dir}/kzg_bn254_{degree}.srs")
    format!("{params_dir}/params{degree}")
}

/// return setup params by reading from file or generate new one
pub fn load_or_create_params(params_dir: &str, degree: usize) -> Result<ParamsKZG<Bn256>> {
    let _path = PathBuf::from(params_dir);

    match metadata(params_dir) {
        Ok(md) => {
            if md.is_file() {
                panic!("{params_dir} should be folder");
            }
        }
        Err(_) => {
            // not exist
            fs::create_dir_all(params_dir)?;
        }
    };

    let params_path = param_path_for_degree(params_dir, degree);
    log::info!("load_or_create_params {}", params_path);
    if Path::new(&params_path).exists() {
        match load_params(&params_path, degree, DEFAULT_SERDE_FORMAT) {
            Ok(r) => return Ok(r),
            Err(e) => {
                log::error!("load params err: {}. Recreating...", e)
            }
        }
    }
    create_params(&params_path, degree)
}

/// load params from file
pub fn load_params(
    params_dir: &str,
    degree: usize,
    serde_format: SerdeFormat,
) -> Result<ParamsKZG<Bn256>> {
    log::info!("start loading params with degree {}", degree);
    let params_path = if metadata(params_dir)?.is_dir() {
        // auto load
        param_path_for_degree(params_dir, degree)
    } else {
        params_dir.to_string()
    };
    let f = File::open(params_path)?;

    // check params file length:
    //   len: 4 bytes
    //   g: 2**DEGREE g1 points, each 32 bytes(256bits)
    //   g_lagrange: 2**DEGREE g1 points, each 32 bytes(256bits)
    //   g2: g2 point, 64 bytes
    //   s_g2: g2 point, 64 bytes
    let file_size = f.metadata()?.len();
    let g1_num = 2 * (1 << degree);
    let g2_num = 2;
    let g1_bytes_len = match serde_format {
        SerdeFormat::Processed => 32,
        SerdeFormat::RawBytes | SerdeFormat::RawBytesUnchecked => 64,
    };
    let g2_bytes_len = 2 * g1_bytes_len;
    let expected_len = 4 + g1_num * g1_bytes_len + g2_num * g2_bytes_len;
    if file_size != expected_len {
        return Err(anyhow::format_err!("invalid params file len {} for degree {}. check DEGREE or remove the invalid params file", file_size, degree));
    }

    let p = ParamsKZG::<Bn256>::read_custom::<_>(&mut BufReader::new(f), serde_format)?;
    log::info!("load params successfully!");
    Ok(p)
}

/// create params and write it into file
pub fn create_params(params_path: &str, degree: usize) -> Result<ParamsKZG<Bn256>> {
    log::info!("start creating params with degree {}", degree);
    // The params used for production need to be generated from a trusted setup ceremony.
    // Here we use a deterministic seed to generate params. This method is unsafe for production usage.
    let seed_str = read_env_var("PARAM_SEED", "bb4b94a1bbef58c4b5fcda6c900629b5".to_string());
    let seed_fr = if seed_str.is_empty() {
        log::info!("use OsRng to create params");
        Fr::random(OsRng)
    } else {
        let bytes = &mut [0u8; 64];
        bytes[..32].clone_from_slice(&seed_str.as_bytes()[..32]);
        Fr::from_bytes_wide(bytes)
    };
    let params: ParamsKZG<Bn256> = ParamsKZG::<Bn256>::unsafe_setup_with_s(degree as u32, seed_fr);
    let mut params_buf = Vec::new();
    params.write_custom(&mut params_buf, DEFAULT_SERDE_FORMAT)?;

    let mut params_file = File::create(params_path)?;
    params_file.write_all(&params_buf[..])?;
    log::info!("create params successfully!");

    Ok(params)
}

/// get a block-result from file
pub fn get_block_trace_from_file<P: AsRef<Path>>(path: P) -> BlockTrace {
    let mut buffer = Vec::new();
    let mut f = File::open(&path).unwrap();
    f.read_to_end(&mut buffer).unwrap();

    serde_json::from_slice::<BlockTrace>(&buffer).unwrap_or_else(|e1| {
        serde_json::from_slice::<BlockTraceJsonRpcResult>(&buffer)
            .map_err(|e2| {
                panic!(
                    "unable to load BlockTrace from {:?}, {:?}, {:?}",
                    path.as_ref(),
                    e1,
                    e2
                )
            })
            .unwrap()
            .result
    })
}

pub fn read_env_var<T: Clone + FromStr>(var_name: &'static str, default: T) -> T {
    std::env::var(var_name)
        .map(|s| s.parse::<T>().unwrap_or_else(|_| default.clone()))
        .unwrap_or(default)
}

#[derive(Debug)]
pub struct BatchMetric {
    pub num_block: usize,
    pub num_tx: usize,
    pub num_step: usize,
}

pub fn metric_of_witness_block(block: &witness::Block<Fr>) -> BatchMetric {
    BatchMetric {
        num_block: block.context.ctxs.len(),
        num_tx: block.txs.len(),
        num_step: block.txs.iter().map(|tx| tx.steps.len()).sum::<usize>(),
    }
}

// Return the output dir.
pub fn init_env_and_log(id: &str) -> String {
    dotenv::dotenv().ok();
    let output_dir = create_output_dir(id);

    LOGGER.call_once(|| {
        // TODO: cannot support complicated `RUST_LOG` for now.
        let log_level = read_env_var("RUST_LOG", "INFO".to_string());
        let log_level = LevelFilter::from_str(&log_level).unwrap_or(LevelFilter::Info);

        let mut log_file_path = PathBuf::from(output_dir.clone());
        log_file_path.push("log.txt");
        let log_file = FileAppender::builder().build(log_file_path).unwrap();

        let stderr = ConsoleAppender::builder().target(Target::Stderr).build();

        let config = Config::builder()
            .appenders([
                Appender::builder().build("log-file", Box::new(log_file)),
                Appender::builder().build("stderr", Box::new(stderr)),
            ])
            .build(
                Root::builder()
                    .appender("log-file")
                    .appender("stderr")
                    .build(log_level),
            )
            .unwrap();

        log4rs::init_config(config).unwrap();

        log::info!("git version {}", GIT_VERSION);
    });

    output_dir
}

fn create_output_dir(id: &str) -> String {
    let mode = read_env_var("MODE", "multi".to_string());
    let output = read_env_var(
        "OUTPUT_DIR",
        format!(
            "{}_output_{}_{}",
            id,
            mode,
            Utc::now().format("%Y%m%d_%H%M%S")
        ),
    );

    let output_dir = PathBuf::from_str(&output).unwrap();
    fs::create_dir_all(output_dir).unwrap();

    output
}
