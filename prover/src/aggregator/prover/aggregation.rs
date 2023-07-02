use super::Prover;
use aggregator::AggregationCircuit;
use halo2_proofs::{halo2curves::bn256::Fr, poly::commitment::Params};
use rand::Rng;
use snark_verifier_sdk::Snark;
use zkevm_circuits::evm_circuit::witness::Block;

impl Prover {
    pub fn gen_agg_snark(
        &mut self,
        id: &str,
        degree: u32,
        mut rng: impl Rng + Send,
        blocks: &[Block<Fr>],
        snarks: Vec<Snark>,
    ) -> Snark {
        let mut params = self.params.clone();
        params.downsize(degree);

        let chunk_hashes: Vec<_> = blocks.iter().map(Into::into).collect();

        let circuit = AggregationCircuit::new(&params, &snarks, &mut rng, &chunk_hashes);
        self.gen_snark(id, &mut rng, &params, circuit)
    }
}
