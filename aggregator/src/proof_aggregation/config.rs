/// Config for BatchCircuit
#[derive(Clone, Debug)]
pub struct AggregationCircuitConfig<F: Field> {
    /// Instance column stores the aggregated rpi hash digest
    pub(crate) hash_digest_column: Column<Instance>,

    /// Keccak circuit config
    pub(crate) keccak_circuit_config: KeccakCircuitConfig<F>,
}


impl<F:Field> SubCircuitConfig for AggregationCircuitConfig<F> {
    type ConfigArgs = AggregationCircuitConfig;

     /// Return a new BatchCircuitConfig
     fn new(meta: &mut ConstraintSystem<F>, config_args: Self::ConfigArgs) -> Self {
        todo!()
     }
} 