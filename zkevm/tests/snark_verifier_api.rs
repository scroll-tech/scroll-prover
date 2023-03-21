use std::path::Path;

use application::StandardPlonk;
use bus_mapping::{circuit_input_builder::CircuitsParams, mock::BlockData};
use eth_types::geth_types::GethData;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::halo2::gen_proof_shplonk;
use snark_verifier_sdk::CircuitExt;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{gen_snark_shplonk, PoseidonTranscript, POSEIDON_SPEC},
    NativeLoader,
};
use zkevm_circuits::evm_circuit::EvmCircuit;
use zkevm_circuits::witness::block_convert;

mod test_util;
use test_util::{
    init, load_block_traces_for_test, parse_trace_path_from_mode, PARAMS_DIR, SEED_PATH,
};

fn test_circuit() -> EvmCircuit<Fr> {
    let empty_data: GethData = mock::TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b)
        .unwrap()
        .into();

    let mut builder =
        BlockData::new_from_geth_data_with_params(empty_data.clone(), CircuitsParams::default())
            .new_circuit_input_builder();

    builder
        .handle_block(&empty_data.eth_block, &empty_data.geth_traces)
        .unwrap();

    let block = block_convert(&builder.block, &builder.code_db).unwrap();

    EvmCircuit::<Fr>::new(block)
}

mod application {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
        poly::Rotation,
    };
    use rand::RngCore;
    use snark_verifier_sdk::CircuitExt;

    #[derive(Clone, Copy)]
    pub struct StandardPlonkConfig {
        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        q_a: Column<Fixed>,
        q_b: Column<Fixed>,
        q_c: Column<Fixed>,
        q_ab: Column<Fixed>,
        constant: Column<Fixed>,
        #[allow(dead_code)]
        instance: Column<Instance>,
    }

    impl StandardPlonkConfig {
        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
            let [a, b, c] = [(); 3].map(|_| meta.advice_column());
            let [q_a, q_b, q_c, q_ab, constant] = [(); 5].map(|_| meta.fixed_column());
            let instance = meta.instance_column();

            [a, b, c].map(|column| meta.enable_equality(column));

            meta.create_gate(
                "q_a·a + q_b·b + q_c·c + q_ab·a·b + constant + instance = 0",
                |meta| {
                    let [a, b, c] =
                        [a, b, c].map(|column| meta.query_advice(column, Rotation::cur()));
                    let [q_a, q_b, q_c, q_ab, constant] = [q_a, q_b, q_c, q_ab, constant]
                        .map(|column| meta.query_fixed(column, Rotation::cur()));
                    let instance = meta.query_instance(instance, Rotation::cur());
                    Some(
                        q_a * a.clone()
                            + q_b * b.clone()
                            + q_c * c
                            + q_ab * a * b
                            + constant
                            + instance,
                    )
                },
            );

            StandardPlonkConfig {
                a,
                b,
                c,
                q_a,
                q_b,
                q_c,
                q_ab,
                constant,
                instance,
            }
        }
    }

    #[derive(Clone, Default)]
    pub struct StandardPlonk(Fr);

    impl StandardPlonk {
        pub fn rand<R: RngCore>(mut rng: R) -> Self {
            Self(Fr::from(rng.next_u32() as u64))
        }
    }

    impl CircuitExt<Fr> for StandardPlonk {
        fn num_instance(&self) -> Vec<usize> {
            vec![1]
        }

        fn instances(&self) -> Vec<Vec<Fr>> {
            vec![vec![self.0]]
        }
    }

    impl Circuit<Fr> for StandardPlonk {
        type Config = StandardPlonkConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            meta.set_minimum_degree(4);
            StandardPlonkConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "",
                |mut region| {
                    region.assign_advice(|| "", config.a, 0, || Value::known(self.0))?;
                    region.assign_fixed(|| "", config.q_a, 0, || Value::known(-Fr::one()))?;
                    region.assign_advice(|| "", config.a, 1, || Value::known(-Fr::from(5u64)))?;
                    for (idx, column) in (1..).zip([
                        config.q_a,
                        config.q_b,
                        config.q_c,
                        config.q_ab,
                        config.constant,
                    ]) {
                        region.assign_fixed(
                            || "",
                            column,
                            1,
                            || Value::known(Fr::from(idx as u64)),
                        )?;
                    }
                    let a = region.assign_advice(|| "", config.a, 2, || Value::known(Fr::one()))?;
                    a.copy_advice(|| "", &mut region, config.b, 3)?;
                    a.copy_advice(|| "", &mut region, config.c, 4)?;

                    Ok(())
                },
            )
        }
    }
}

#[test]
fn test_snark_verifier_api() {
    let k = 15;
    let k_agg = 22;

    init();

    let mut rng = XorShiftRng::from_seed([0u8; 16]);

    let circuit = StandardPlonk::rand(&mut rng);
    let params_inner = gen_srs(k);
    let params_outer = gen_srs(k_agg);
    let pk_inner = gen_pk(
        &params_inner,
        &circuit,
        Some(Path::new("data/inner.pkey")),
    );
    let snark = gen_snark_shplonk(
        &params_inner,
        &pk_inner,
        circuit,
        &mut rng,
        Some(Path::new("data/inner.snark")),
    );
    println!("finished snark generation");

    let snarks = [snark];
    let agg_circuit = AggregationCircuit::new(&params_outer, snarks, &mut rng);
    let pk_outer = gen_pk(
        &params_outer,
        &agg_circuit,
        Some(Path::new("data/outer.pkey")),
    );

    let instances = agg_circuit.instances();
    let proof = gen_proof_shplonk(
        &params_outer,
        &pk_outer,
        agg_circuit.clone(),
        instances,
        &mut rng,
        Some((Path::new("data/outer.instance"), Path::new("data/outer.snark"))),
    );

    println!("finished aggregation generation");

}
