
use super::{TargetCircuit, DEGREE};

use anyhow::bail;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::witness;
use zkevm_circuits::util::SubCircuit;

pub struct ZktrieCircuit {}

impl TargetCircuit for ZktrieCircuit {
    type Inner = ZktrieCircuitImpl<Fr>;

    fn name() -> String {
        "zktrie".to_string()
    }

    fn from_witness_block(
        witness_block: &witness::Block<Fr>,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let inner = ZktrieCircuitImpl::new_from_block(witness_block);
        let instance = vec![];
        Ok((inner, instance))
    }
}

/*
fn trie_data_from_blocks<'d>(
    block_traces: impl IntoIterator<Item = &'d BlockTrace>,
) -> EthTrie<Fr> {
    let mut trie_data: EthTrie<Fr> = Default::default();
    let mut total_tx_num = 0usize;
    for (idx, block_trace) in block_traces.into_iter().enumerate() {
        let storage_ops: Vec<AccountOp<_>> = block_trace
            .mpt_witness
            .iter()
            .map(|tr| tr.try_into().unwrap())
            .collect();
        trie_data.add_ops(storage_ops);
        total_tx_num += block_trace.execution_results.len();
        log::debug!(
            "after {}th block(tx num: {}), total tx num: {}, zktrie row num: {:?}",
            idx,
            block_trace.transactions.len(),
            total_tx_num,
            trie_data.use_rows()
        );
    }

    trie_data
}
*/


