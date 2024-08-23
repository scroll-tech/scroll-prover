use prover::{BlockTrace, ChunkProof};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[cfg(feature = "batch-prove")]
use prover::{BatchHeader, MAX_AGG_SNARKS};

#[cfg(feature = "batch-prove")]
pub fn prove_batch(
    id: &str,
    chunk_proofs: Vec<ChunkProof>,
    batch_header: BatchHeader<MAX_AGG_SNARKS>,
) {
    use integration::prove::get_blob_from_chunks;
    use itertools::Itertools;
    use prover::BatchProvingTask;

    let chunk_infos = chunk_proofs
        .iter()
        .map(|p| p.chunk_info.clone())
        .collect_vec();
    let blob_bytes = get_blob_from_chunks(&chunk_infos);
    let batch = BatchProvingTask {
        chunk_proofs,
        batch_header,
        blob_bytes,
    };
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

pub fn prove_chunk(id: &str, traces: Vec<BlockTrace>) -> Option<ChunkProof> {
    let result = catch_unwind(AssertUnwindSafe(|| {
        #[cfg(not(feature = "chunk-prove"))]
        let proof = None::<ChunkProof>;

        #[cfg(feature = "inner-prove")]
        {
            let witness_block =
                prover::zkevm::circuit::block_traces_to_witness_block(traces.clone()).unwrap();
            prover::test::inner_prove(id, &witness_block);
        }
        #[cfg(feature = "chunk-prove")]
        let proof = Some(prover::test::chunk_prove(
            id,
            prover::ChunkProvingTask::from(traces),
        ));
        #[cfg(not(any(feature = "inner-prove", feature = "chunk-prove")))]
        mock_prove(id, traces);

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
fn mock_prove(id: &str, traces: Vec<BlockTrace>) {
    use prover::{inner::Prover, zkevm::circuit::SuperCircuit};

    log::info!("{id}: mock-prove BEGIN");

    Prover::<SuperCircuit>::mock_prove_target_circuit_chunk(traces)
        .unwrap_or_else(|err| panic!("{id}: failed to mock-prove: {err}"));

    log::info!("{id}: mock-prove END");
}
