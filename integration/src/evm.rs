use revm::{
    primitives::{Env, ExecutionResult, Output, SpecId, TxEnv, TxKind},
    Evm, InMemoryDB,
};

/// Deploy contract and then call with calldata.
/// Returns gas_used of call to deployed contract if both transactions are successful.
pub fn deploy_and_call(deployment_code: Vec<u8>, calldata: Vec<u8>) -> Result<u64, String> {
    let mut env = Box::<Env>::default();
    env.tx = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TxKind::Create,
        data: deployment_code.into(),
        ..Default::default()
    };
    let mut db = InMemoryDB::default();
    let mut evm = Evm::builder()
        .with_spec_id(SpecId::CANCUN)
        .with_db(&mut db)
        .with_env(env.clone())
        .build();
    let result = evm.transact_commit().unwrap();
    let contract = match result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(contract)),
            ..
        } => contract,
        ExecutionResult::Revert { gas_used, output } => {
            return Err(format!(
                "Contract deployment transaction reverts with gas_used {gas_used} and output {:#x}",
                output
            ))
        }
        ExecutionResult::Halt { reason, gas_used } => return Err(format!(
            "Contract deployment transaction halts unexpectedly with gas_used {gas_used} and reason {:?}",
            reason
        )),
        _ => unreachable!(),
    };
    drop(evm);

    env.tx = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TxKind::Call(contract),
        data: calldata.into(),
        ..Default::default()
    };
    let mut evm = Evm::builder()
        .with_spec_id(SpecId::CANCUN)
        .with_db(&mut db)
        .with_env(env)
        .build();
    let result = evm.transact_commit().unwrap();
    match result {
        ExecutionResult::Success { gas_used, .. } => Ok(gas_used),
        ExecutionResult::Revert { gas_used, output } => Err(format!(
            "Contract call transaction reverts with gas_used {gas_used} and output {:#x}",
            output
        )),
        ExecutionResult::Halt { reason, gas_used } => Err(format!(
            "Contract call transaction halts unexpectedly with gas_used {gas_used} and reason {:?}",
            reason
        )),
    }
}
