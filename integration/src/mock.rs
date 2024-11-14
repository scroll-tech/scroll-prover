use anyhow::bail;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use prover::{
    eth_types::l2_types::BlockTrace,
    zkevm_circuits::{super_circuit::params::ScrollSuperCircuit, util::SubCircuit, witness::Block},
};
use snark_verifier_sdk::CircuitExt;

use prover::{chunk_trace_to_witness_block, metric_of_witness_block, INNER_DEGREE};

pub fn mock_prove_target_circuit_chunk(block_traces: Vec<BlockTrace>) -> anyhow::Result<()> {
    let witness_block = chunk_trace_to_witness_block(block_traces)?;
    mock_prove_witness_block(&witness_block)
}

pub fn mock_prove_witness_block(witness_block: &Block) -> anyhow::Result<()> {
    log::info!(
        "mock proving chunk, chunk metric {:?}",
        metric_of_witness_block(witness_block)
    );
    let circuit = ScrollSuperCircuit::new_from_block(witness_block);
    let prover = MockProver::<Fr>::run(*INNER_DEGREE, &circuit, circuit.instances())?;
    if let Err(errs) = prover.verify_par() {
        log::error!("err num: {}", errs.len());
        for err in &errs {
            log::error!("{}", err);
        }
        bail!("{:#?}", errs);
    }
    log::info!(
        "mock prove done. chunk metric: {:?}",
        metric_of_witness_block(witness_block),
    );
    Ok(())
}
