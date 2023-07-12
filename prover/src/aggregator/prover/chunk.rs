use super::Prover;
use crate::{
    config::INNER_DEGREE,
    io::{load_snark, write_snark},
    utils::{gen_rng, metric_of_witness_block},
    zkevm::circuit::{SuperCircuit, TargetCircuit},
};
use anyhow::Result;
use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::{gen_snark_shplonk, Snark};
use zkevm_circuits::evm_circuit::witness::Block;

impl Prover {
    pub fn gen_chunk_snark<C: TargetCircuit>(
        &mut self,
        witness_block: &Block<Fr>,
    ) -> Result<Snark> {
        log::info!(
            "Proving the chunk: {:?}",
            metric_of_witness_block(witness_block)
        );

        let (circuit, _instance) = C::from_witness_block(witness_block)?;
        let (params, pk) =
            self.params_and_pk(&C::name(), &C::dummy_inner_circuit(), *INNER_DEGREE)?;
        let snark = gen_snark_shplonk(params, pk, circuit, &mut gen_rng(), None::<String>);

        Ok(snark)
    }

    pub fn load_or_gen_chunk_snark(
        &mut self,
        id: &str,
        witness_block: Block<Fr>,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        let file_path = format!("{}/{}_chunk_snark.json", output_dir.unwrap_or_default(), id);

        match output_dir.and_then(|_| load_snark(&file_path).ok().flatten()) {
            Some(snark) => Ok(snark),
            None => {
                let res = self.gen_chunk_snark::<SuperCircuit>(&witness_block);
                if let (Some(_), Ok(snark)) = (output_dir, &res) {
                    write_snark(&file_path, &snark);
                }

                res
            }
        }
    }
}
