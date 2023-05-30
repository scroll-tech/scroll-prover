use eth_types::Field;
use halo2_proofs::{circuit::Value, halo2curves::CurveAffine};
use snark_verifier::{pcs::kzg::KzgSuccinctVerifyingKey, Protocol};
use zkevm_circuits::{util::SubCircuit, witness::Block};

use crate::public_input_aggregation::LOG_DEGREE;

#[derive(Clone, Debug)]
pub struct SnarkWitness<C, F>
where
    C: CurveAffine<ScalarExt = F>,
    F: Field,
{
    pub protocol: Protocol<C>,
    pub instances: Vec<Vec<F>>,
    pub proof: Value<Vec<u8>>,
}

/// Aggregation circuit that re-exposes any public inputs from aggregated snarks
///
#[derive(Clone, Debug)]
pub struct AggregationCircuit<C, F>
where
    C: CurveAffine<ScalarExt = F>,
    F: Field,
{
    pub(crate) svk: KzgSuccinctVerifyingKey<C>,
    pub(crate) snarks: Vec<SnarkWitness<C, F>>,
    // accumulation scheme proof, private input
    pub(crate) as_proof: Value<Vec<u8>>,
}

impl<C, F> SubCircuit<F> for AggregationCircuit<C, F>
where
    C: CurveAffine<ScalarExt = F>,
    F: Field,
{
    // TODO
    type Config = ();

    fn new_from_block(_block: &Block<F>) -> Self {
        // we cannot instantiate a new Self from a single block
        unimplemented!()
    }

    /// Return the minimum number of rows required to prove the block
    /// Row numbers without/with padding are both returned.
    fn min_num_rows_block(_block: &Block<F>) -> (usize, usize) {
        (1 << LOG_DEGREE, 1 << LOG_DEGREE)
    }

    /// Compute the public inputs for this circuit.
    /// It is simply the concatenation of all its inner snarks.
    fn instance(&self) -> Vec<Vec<F>> {
        self.snarks.iter().flat_map(|x| x.instances).collect()
    }

    /// Make the assignments to the BatchHashCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        todo!()
    }
}
