use ark_std::test_rng;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

use crate::BatchHashCircuit;
use zkevm_circuits::util::SubCircuit;

use super::LOG_DEGREE;

#[test]
fn test_pi_aggregation_circuit() {
    let mut rng = test_rng();
    let chunks_per_batch = 8;

    let circuit = BatchHashCircuit::<Fr>::mock_batch_hash_circuit(&mut rng, chunks_per_batch);
    let instance = circuit.instance();

    let mock_prover = MockProver::<Fr>::run(LOG_DEGREE, &circuit, instance).unwrap();

    mock_prover.assert_satisfied_par()
}
