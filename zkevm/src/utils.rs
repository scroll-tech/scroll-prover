use crate::circuit::{block_result_to_circuits, DEGREE};
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::poly::commitment::Params;
use pairing::bn256::{Bn256, Fr, G1Affine};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use types::eth::test::mock_block_result;
use zkevm_circuits::evm_circuit::param::STEP_HEIGHT;

/// generate (randomness, evm_circuit, state_circuit)
pub fn load_randomness_and_circuits() -> (Vec<&'static [Fr]>, impl Circuit<Fr>, impl Circuit<Fr>) {
    let block_result = mock_block_result();
    let (block, evm_circuit, state_circuit) = block_result_to_circuits::<Fr>(block_result).unwrap();
    let power_of_randomness: Vec<Box<[Fr]>> = (1..32)
        .map(|exp| {
            vec![
                block.randomness.pow(&[exp, 0, 0, 0]);
                block.txs.iter().map(|tx| tx.steps.len()).sum::<usize>() * STEP_HEIGHT
            ]
            .into_boxed_slice()
        })
        .collect();
    let randomness = power_of_randomness.iter().map(AsRef::as_ref).collect();
    (randomness, evm_circuit, state_circuit)
}

/// return setup params by reading from file or generate new one
pub fn init_params(params_path: &str) -> Params<G1Affine> {
    log::info!("start init params");

    // Create the `params` file if non-existing.
    let params = match File::open(&params_path) {
        Ok(fs) => Params::read::<_>(&mut BufReader::new(fs)).expect("Failed to read params"),
        Err(_) => {
            let params: Params<G1Affine> = Params::<G1Affine>::unsafe_setup::<Bn256>(DEGREE as u32);
            let mut params_buf = Vec::new();
            params
                .write(&mut params_buf)
                .expect("Failed to write params");

            let mut params_file =
                File::create(&params_path).expect("Failed to create sha256_params");
            params_file
                .write_all(&params_buf[..])
                .expect("Failed to write params to file");

            params
        }
    };
    log::info!("init params successfully!");
    params
}

/// return setup rng by reading from file or generate new one
pub fn init_rng(seed_path: &str) -> XorShiftRng {
    // TODO: use better randomness source
    const RNG_SEED_BYTES: [u8; 16] = [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ];

    // Create the `seed` file if non-existing.
    let seed_path = Path::new(seed_path);
    let rng = if !seed_path.exists() {
        let mut seed_file = File::create(&seed_path).expect("Failed to create rng seed");
        seed_file
            .write_all(RNG_SEED_BYTES.as_slice())
            .expect("Failed to write rng-seed to file");
        XorShiftRng::from_seed(RNG_SEED_BYTES)
    } else {
        let mut seed_fs = File::open(seed_path).expect("Cannot load seed");
        let mut seed = [0_u8; 16];
        seed_fs
            .read_exact(&mut seed)
            .expect("Failed read seed from file");
        XorShiftRng::from_seed(seed)
    };
    rng
}
