use crate::circuit::DEGREE;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::poly::commitment::Params;
use pairing::bn256::{Bn256, Fr, G1Affine};
use std::fs::File;
use std::io::{BufReader, Read, Result, Write};
use std::path::Path;
use zkevm_circuits::evm_circuit::param::STEP_HEIGHT;
use zkevm_circuits::evm_circuit::witness::Block;

/// generate randomness for the block
pub fn load_randomness(block: Block<Fr>) -> Vec<Box<[Fr]>> {
    let power_of_randomness: Vec<Box<[Fr]>> = (1..32)
        .map(|exp| {
            vec![
                block.randomness.pow(&[exp, 0, 0, 0]);
                block.txs.iter().map(|tx| tx.steps.len()).sum::<usize>() * STEP_HEIGHT
            ]
            .into_boxed_slice()
        })
        .collect();
    power_of_randomness
}

/// return setup params by reading from file or generate new one
pub fn load_or_create_params(params_path: &str) -> Result<Params<G1Affine>> {
    if Path::new(params_path).exists() {
        load_params(params_path)
    } else {
        create_params(params_path)
    }
}

pub fn load_params(params_path: &str) -> Result<Params<G1Affine>> {
    log::info!("start load params");
    let f = File::open(params_path)?;
    let p = Params::read::<_>(&mut BufReader::new(f))?;
    log::info!("load params successfully!");
    Ok(p)
}

pub fn create_params(params_path: &str) -> Result<Params<G1Affine>> {
    log::info!("start create params");
    let params: Params<G1Affine> = Params::<G1Affine>::unsafe_setup::<Bn256>(DEGREE as u32);
    let mut params_buf = Vec::new();
    params.write(&mut params_buf)?;

    let mut params_file = File::create(&params_path)?;
    params_file.write_all(&params_buf[..])?;
    log::info!("create params successfully!");
    Ok(params)
}

/// return setup rng by reading from file or generate new one
pub fn load_or_create_seed(seed_path: &str) -> Result<[u8; 16]> {
    if Path::new(seed_path).exists() {
        load_seed(seed_path)
    } else {
        create_seed(seed_path)
    }
}

pub fn load_seed(seed_path: &str) -> Result<[u8; 16]> {
    let mut seed_fs = File::open(seed_path)?;
    let mut seed = [0_u8; 16];
    seed_fs.read_exact(&mut seed)?;
    Ok(seed)
}

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
