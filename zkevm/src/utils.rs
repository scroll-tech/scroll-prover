use crate::circuit::DEGREE;
use halo2_proofs::pairing::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::poly::commitment::Params;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read, Result, Write};
use std::path::Path;
use types::eth::BlockResult;
use zkevm_circuits::evm_circuit::witness::Block;
use zkevm_circuits::state_circuit::StateCircuit;

/// generate randomness for the block
pub fn load_randomness(block: Block<Fr>) -> Vec<Box<[Fr]>> {
    let circuit = StateCircuit::<Fr>::new(block.randomness, block.rws);
    circuit
        .instance()
        .into_iter()
        .map(|col| col.into_boxed_slice())
        .collect()
}

/// return setup params by reading from file or generate new one
pub fn load_or_create_params(params_path: &str) -> Result<Params<G1Affine>> {
    if Path::new(params_path).exists() {
        load_params(params_path)
    } else {
        create_params(params_path)
    }
}

/// load params from file
pub fn load_params(params_path: &str) -> Result<Params<G1Affine>> {
    log::info!("start load params");
    let f = File::open(params_path)?;
    let p = Params::read::<_>(&mut BufReader::new(f))?;
    log::info!("load params successfully!");
    Ok(p)
}

/// create params and write it into file
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
