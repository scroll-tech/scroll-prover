use anyhow::Result;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::halo2curves::FieldExt;

use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs::{self, metadata, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use types::eth::BlockResult;

/// return setup params by reading from file or generate new one
pub fn load_or_create_params(params_dir: &str, degree: usize) -> Result<ParamsKZG<Bn256>> {
    let _path = PathBuf::from(params_dir);

    match metadata(params_dir) {
        Ok(md) => {
            if md.is_file() {
                panic!("{} should be folder", params_dir);
            }
        }
        Err(_) => {
            // not exist
            fs::create_dir_all(params_dir)?;
        }
    };

    let params_path = format!("{}/params{}", params_dir, degree);
    log::info!("load_or_create_params {}", params_path);
    if Path::new(&params_path).exists() {
        match load_params(&params_path, degree) {
            Ok(r) => return Ok(r),
            Err(e) => {
                log::error!("load params err: {}. Recreating...", e)
            }
        }
    }
    create_params(&params_path, degree)
}

/// load params from file
pub fn load_params(params_dir: &str, degree: usize) -> Result<ParamsKZG<Bn256>> {
    log::info!("start loading params with degree {}", degree);
    let params_path = if metadata(params_dir)?.is_dir() {
        // auto load
        format!("{}/params{}", params_dir, degree)
    } else {
        params_dir.to_string()
    };
    let f = File::open(&params_path)?;

    // check params file length:
    //   len: 4 bytes
    //   g: 2**DEGREE g1 points, each 32 bytes(256bits)
    //   g_lagrange: 2**DEGREE g1 points, each 32 bytes(256bits)
    //   g2: g2 point, 64 bytes
    //   s_g2: g2 point, 64 bytes
    let file_size = f.metadata()?.len();
    if file_size != (1 << degree) * 64 + 132 {
        return Err(anyhow::format_err!("invalid params file len {} for degree {}. check DEGREE or remove the invalid params file", file_size, degree));
    }

    let p = Params::read::<_>(&mut BufReader::new(f))?;
    log::info!("load params successfully!");
    Ok(p)
}

/// create params and write it into file
pub fn create_params(params_path: &str, degree: usize) -> Result<ParamsKZG<Bn256>> {
    log::info!("start creating params with degree {}", degree);
    let seed_str = read_env_var("PARAM_SEED", "".to_string());
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
    params.write(&mut params_buf)?;

    let mut params_file = File::create(&params_path)?;
    params_file.write_all(&params_buf[..])?;
    log::info!("create params successfully!");

    Ok(params)
}

/// return random seed by reading from file or generate new one
pub fn load_or_create_seed(seed_path: &str) -> Result<[u8; 16]> {
    if Path::new(seed_path).exists() {
        load_seed(seed_path)
    } else {
        create_seed(seed_path)
    }
}

/// load seed from the file
pub fn load_seed(seed_path: &str) -> Result<[u8; 16]> {
    let mut seed_fs = File::open(seed_path)?;
    let mut seed = [0_u8; 16];
    seed_fs.read_exact(&mut seed)?;
    Ok(seed)
}

/// create the seed and write it into file
pub fn create_seed(seed_path: &str) -> Result<[u8; 16]> {
    // TODO: use better randomness source
    const RNG_SEED_BYTES: [u8; 16] = [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ];

    let mut seed_file = File::create(&seed_path)?;
    seed_file.write_all(RNG_SEED_BYTES.as_slice())?;
    Ok(RNG_SEED_BYTES)
}

/// get a block-result from file
pub fn get_block_result_from_file<P: AsRef<Path>>(path: P) -> BlockResult {
    let mut buffer = Vec::new();
    let mut f = File::open(path).unwrap();
    f.read_to_end(&mut buffer).unwrap();

    #[derive(Deserialize, Serialize, Default)]
    struct RpcJson {
        result: BlockResult,
    }

    let j = serde_json::from_slice::<RpcJson>(&buffer).unwrap();

    j.result
}

pub fn read_env_var<T: Clone + FromStr>(var_name: &'static str, default: T) -> T {
    std::env::var(var_name)
        .map(|s| s.parse::<T>().unwrap_or_else(|_| default.clone()))
        .unwrap_or(default)
}
