use crate::circuit::block_result_to_circuits;
use halo2_proofs::plonk::Circuit;
use pairing::bn256::Fr;
use types::eth::test::mock_block_result;
use zkevm_circuits::evm_circuit::param::STEP_HEIGHT;

pub fn load_randomness_and_circuit() -> (Vec<&'static [Fr]>, impl Circuit<Fr>, impl Circuit<Fr>) {
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
