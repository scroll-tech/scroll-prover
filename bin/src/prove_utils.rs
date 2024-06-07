use prover::{ChunkProof, WitnessBlock};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[cfg(feature = "batch-prove")]
pub fn prove_batch(id: &str, chunk_proofs: Vec<ChunkProof>) {
    use prover::BatchProvingTask;

    let batch = BatchProvingTask { chunk_proofs };
    let result = catch_unwind(AssertUnwindSafe(|| prover::test::batch_prove(id, batch)));

    match result {
        Ok(_) => log::info!("{id}: succeeded to prove batch"),
        Err(err) => {
            let panic_err = if let Some(s) = err.downcast_ref::<String>() {
                s.to_string()
            } else if let Some(s) = err.downcast_ref::<&str>() {
                s.to_string()
            } else {
                format!("unable to get panic info {err:?}")
            };
            log::error!("{id}: failed to prove batch:\n{panic_err:?}");
        }
    }
}

pub fn prove_chunk(id: &str, witness_block: &WitnessBlock) -> Option<ChunkProof> {
    let result = catch_unwind(AssertUnwindSafe(|| {
        #[cfg(not(feature = "chunk-prove"))]
        let proof = None::<ChunkProof>;

        #[cfg(feature = "inner-prove")]
        prover::test::inner_prove(id, witness_block);
        #[cfg(feature = "chunk-prove")]
        let proof = Some(prover::test::chunk_prove(id, witness_block));
        #[cfg(not(any(feature = "inner-prove", feature = "chunk-prove")))]
        mock_prove(id, witness_block);

        proof
    }));

    match result {
        Ok(proof) => {
            log::info!("{id}: succeeded to prove chunk");
            proof
        }
        Err(err) => {
            let panic_err = if let Some(s) = err.downcast_ref::<String>() {
                s.to_string()
            } else if let Some(s) = err.downcast_ref::<&str>() {
                s.to_string()
            } else {
                format!("unable to get panic info {err:?}")
            };
            log::error!("{id}: failed to prove chunk:\n{panic_err:?}");

            None
        }
    }
}

#[cfg(not(any(feature = "inner-prove", feature = "chunk-prove")))]
fn mock_prove(id: &str, witness_block: &WitnessBlock) {
    use prover::{inner::Prover, zkevm::circuit::SuperCircuit};

    log::info!("{id}: mock-prove BEGIN");

    Prover::<SuperCircuit>::mock_prove_witness_block(witness_block)
        .unwrap_or_else(|err| panic!("{id}: failed to mock-prove: {err}"));

    log::info!("{id}: mock-prove END");
}
