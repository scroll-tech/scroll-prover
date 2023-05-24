use zkevm_circuits::{
    keccak_circuit::{KeccakCircuitConfig, KeccakCircuitConfigArgs},
    table::KeccakTable,
    util::{Challenges, SubCircuitConfig},
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Column, ConstraintSystem, Error, Expression, Instance},
};

use crate::LOG_DEGREE;

/// Config for BatchCircuit
#[derive(Clone, Debug)]
pub struct BatchCircuitConfig<F: Field> {
    /// Log of the degree of the circuit
    pub(crate) log_degree: usize,

    /// Instance column stores the aggregated rpi hash digest
    pub(crate) hash_digest_column: Column<Instance>,

    /// Keccak circuit config
    pub(crate) keccak_circuit_config: KeccakCircuitConfig<F>,
}

#[derive(Clone, Debug)]
pub struct BatchCircuitConfigArgs<F: Field> {
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for BatchCircuitConfig<F> {
    type ConfigArgs = BatchCircuitConfigArgs<F>;

    /// Return a new BatchCircuitConfig
    fn new(meta: &mut ConstraintSystem<F>, config_args: Self::ConfigArgs) -> Self {
        // hash configuration
        let keccak_circuit_config = {
            let keccak_table = KeccakTable::construct(meta);

            let keccak_circuit_config_args = KeccakCircuitConfigArgs {
                keccak_table,
                challenges: config_args.challenges,
            };

            KeccakCircuitConfig::new(meta, keccak_circuit_config_args)
        };

        // The current code base is hardcoded for KeccakCircuit configured
        // with 300 rows and 87 columns per hash call.
        let columns = keccak_circuit_config.cell_manager.columns();

        assert_eq!(
            columns.len(),
            87,
            "cell manager configuration does not match the hard coded setup"
        );

        // enabling equality for preimage and digest columns
        meta.enable_equality(columns[6].advice);
        // digest column
        meta.enable_equality(columns.last().unwrap().advice);

        // Instance column stores the output of the hash
        let hash_digest_column = meta.instance_column();
        // public input column
        meta.enable_equality(hash_digest_column);

        BatchCircuitConfig {
            log_degree: LOG_DEGREE as usize,
            hash_digest_column,
            keccak_circuit_config,
        }
    }
}

impl<F: Field> BatchCircuitConfig<F> {
    /// Input the hash input bytes,
    /// assign the circuit for hash function,
    /// return cells for the hash inputs and digests.
    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        challenges: Challenges<Value<F>>,
        preimages: &[Vec<u8>],
    ) -> Result<
        (
            Vec<Vec<AssignedCell<F, F>>>, // input cells
            Vec<Vec<AssignedCell<F, F>>>, // digest cells
        ),
        Error,
    > {
        todo!()
    }
}
