use super::{MAX_CALLDATA, MAX_EXP_STEPS, MAX_RWS, MAX_TXS};
use crate::circuit::{
    TargetCircuit, AUTO_TRUNCATE, CHAIN_ID, DEGREE, MAX_BYTECODE, MAX_INNER_BLOCKS,
    MAX_KECCAK_ROWS, MAX_MPT_ROWS,
};
use anyhow::bail;
use bus_mapping::circuit_input_builder::{self, BlockHead, CircuitInputBuilder, CircuitsParams};
use bus_mapping::state_db::{Account, CodeDB, StateDB};
use eth_types::evm_types::OpcodeId;
use eth_types::ToAddress;
use ethers_core::types::{Bytes, U256};
use halo2_proofs::halo2curves::bn256::Fr;
use is_even::IsEven;
use itertools::Itertools;
use mpt_zktrie::state::ZktrieState;
use std::time::Instant;
use types::eth::{BlockTrace, EthBlock, ExecStep};
use zkevm_circuits::evm_circuit::witness::block_apply_mpt_state;
use zkevm_circuits::evm_circuit::witness::{block_convert, Block};
use zkevm_circuits::util::SubCircuit;

pub const SUB_CIRCUIT_NAMES: [&str; 11] = [
    "evm", "state", "bytecode", "copy", "keccak", "tx", "rlp", "exp", "pi", "poseidon", "mpt",
];

// TODO: optimize it later
pub fn calculate_row_usage_of_trace(block_trace: &BlockTrace) -> Result<Vec<usize>, anyhow::Error> {
    let witness_block = block_traces_to_witness_block(std::slice::from_ref(block_trace))?;
    calculate_row_usage_of_witness_block(&witness_block)
}
pub fn calculate_row_usage_of_witness_block(
    witness_block: &Block<Fr>,
) -> Result<Vec<usize>, anyhow::Error> {
    let rows =
        <crate::circuit::SuperCircuit as TargetCircuit>::Inner::min_num_rows_block_subcircuits(
            witness_block,
        )
        .0;

    log::debug!(
        "row usage of block {:?}, tx num {:?}, tx len sum {}, rows needed {:?}",
        witness_block.context.first_or_default().number,
        witness_block.txs.len(),
        witness_block
            .txs
            .iter()
            .map(|t| t.call_data_length)
            .sum::<usize>(),
        SUB_CIRCUIT_NAMES.iter().zip_eq(rows.iter())
    );
    Ok(rows)
}

// FIXME: we need better API name for this.
// This function also mutates the block trace.
/// ...
pub fn check_batch_capacity(block_traces: &mut Vec<BlockTrace>) -> Result<(), anyhow::Error> {
    let block_traces_len = block_traces.len();
    let total_tx_count = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    let total_tx_len_sum = block_traces
        .iter()
        .flat_map(|b| b.transactions.iter().map(|t| t.data.len()))
        .sum::<usize>();
    log::info!(
        "check capacity of block traces, num_block {}, num_tx {}, tx total len {}",
        block_traces_len,
        total_tx_count,
        total_tx_len_sum
    );

    if block_traces_len > MAX_INNER_BLOCKS {
        bail!("too many blocks");
    }

    if !*AUTO_TRUNCATE {
        log::debug!("AUTO_TRUNCATE=false, keep batch as is");
        return Ok(());
    }

    let t = Instant::now();
    let mut acc = Vec::new();
    let mut truncate_idx = block_traces.len();
    for (idx, block) in block_traces.iter().enumerate() {
        let usage = calculate_row_usage_of_trace(block)?;
        if acc.is_empty() {
            acc = usage;
        } else {
            acc.iter_mut().zip(usage.iter()).for_each(|(acc, usage)| {
                *acc += usage;
            });
        }
        let rows = itertools::max(&acc).unwrap();
        let rows_and_names: Vec<(_, _)> = SUB_CIRCUIT_NAMES
            .iter()
            .zip_eq(acc.iter())
            .collect::<Vec<(_, _)>>();
        log::debug!(
            "row usage after block {}({:?}): {}, {:?}",
            idx,
            block.header.number,
            rows,
            rows_and_names
        );
        if *rows >= (1 << *DEGREE) - 256 {
            log::warn!("truncate blocks [{}..{})", idx, block_traces_len);
            truncate_idx = idx;
            break;
        }
    }
    log::debug!("check_batch_capacity takes {:?}", t.elapsed());
    block_traces.truncate(truncate_idx);
    let total_tx_count2 = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    if total_tx_count != 0 && total_tx_count2 == 0 {
        // the circuit cannot even prove the first non-empty block...
        bail!("circuit capacity not enough");
    }
    Ok(())
}

pub fn block_traces_to_witness_block(
    block_traces: &[BlockTrace],
) -> Result<Block<Fr>, anyhow::Error> {
    let old_root = if block_traces.is_empty() {
        eth_types::Hash::zero()
    } else {
        block_traces[0].storage_trace.root_before
    };
    let zktrie_state = ZktrieState::from_trace_with_additional(
        old_root,
        block_traces.iter().rev().flat_map(|block| {
            block.storage_trace.proofs.iter().flat_map(|kv_map| {
                kv_map
                    .iter()
                    .map(|(k, bts)| (k, bts.iter().map(Bytes::as_ref)))
            })
        }),
        block_traces.iter().rev().flat_map(|block| {
            block
                .storage_trace
                .storage_proofs
                .iter()
                .flat_map(|(k, kv_map)| {
                    kv_map
                        .iter()
                        .map(move |(sk, bts)| (k, sk, bts.iter().map(Bytes::as_ref)))
                })
        }),
        block_traces.iter().rev().flat_map(|block| {
            block
                .storage_trace
                .deletion_proofs
                .iter()
                .map(Bytes::as_ref)
        }),
    )?;

    let chain_ids = block_traces
        .iter()
        .map(|block_trace| block_trace.chain_id)
        .collect::<Vec<U256>>();

    let chain_id = if !chain_ids.is_empty() {
        chain_ids[0]
    } else {
        (*CHAIN_ID).into()
    };

    let mut state_db = zktrie_state.state().clone();

    let (zero_coinbase_exist, _) = state_db.get_account(&Default::default());
    if !zero_coinbase_exist {
        state_db.set_account(&Default::default(), Account::zero());
    }

    let code_db = build_codedb(&state_db, block_traces)?;
    let circuit_params = CircuitsParams {
        max_evm_rows: MAX_RWS,
        max_rws: MAX_RWS,
        max_copy_rows: MAX_RWS,
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_bytecode: MAX_BYTECODE,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_keccak_rows: MAX_KECCAK_ROWS,
        max_exp_steps: MAX_EXP_STEPS,
        max_mpt_rows: MAX_MPT_ROWS,
    };
    let mut builder_block = circuit_input_builder::Block::from_headers(&[], circuit_params);
    builder_block.chain_id = chain_id;
    builder_block.prev_state_root = U256::from(zktrie_state.root());
    let mut builder = CircuitInputBuilder::new(state_db.clone(), code_db, &builder_block);
    for (idx, block_trace) in block_traces.iter().enumerate() {
        let is_last = idx == block_traces.len() - 1;
        let eth_block: EthBlock = block_trace.clone().into();

        let mut geth_trace = Vec::new();
        for result in &block_trace.execution_results {
            geth_trace.push(result.into());
        }
        // TODO: Get the history_hashes.
        let mut header = BlockHead::new(chain_id, Vec::new(), &eth_block)?;
        // override zeroed minder field with additional "coinbase" field in blocktrace
        if let Some(address) = block_trace.coinbase.address {
            header.coinbase = address;
        }

        builder.block.headers.insert(header.number.as_u64(), header);
        builder.handle_block_inner(&eth_block, geth_trace.as_slice(), false, is_last)?;

        let per_block_metric = false;
        if per_block_metric {
            let t = Instant::now();
            let block = block_convert::<Fr>(&builder.block, &builder.code_db)?;
            log::debug!("block convert time {:?}", t.elapsed());
            let rows =
                <crate::circuit::SuperCircuit as TargetCircuit>::Inner::min_num_rows_block(&block);
            log::debug!(
                "after block {}, tx num {:?}, tx len sum {}, rows needed {:?}. estimate time: {:?}",
                idx,
                builder.block.txs().len(),
                builder
                    .block
                    .txs()
                    .iter()
                    .map(|t| t.input.len())
                    .sum::<usize>(),
                rows,
                t.elapsed()
            );
        }
    }

    builder.set_value_ops_call_context_rwc_eor();
    builder.set_end_block()?;

    let mut witness_block = block_convert(&builder.block, &builder.code_db)?;
    log::debug!(
        "witness_block.circuits_params {:?}",
        witness_block.circuits_params
    );

    block_apply_mpt_state(&mut witness_block, zktrie_state);
    Ok(witness_block)
}

pub fn decode_bytecode(bytecode: &str) -> Result<Vec<u8>, anyhow::Error> {
    let mut stripped = if let Some(stripped) = bytecode.strip_prefix("0x") {
        stripped.to_string()
    } else {
        bytecode.to_string()
    };

    let bytecode_len = stripped.len() as u64;
    if !bytecode_len.is_even() {
        stripped = format!("0{stripped}");
    }

    hex::decode(stripped).map_err(|e| e.into())
}
/*
#[derive(Debug, Clone)]
struct PoseidonCodeHash {
    bytes_in_field: usize,
}

impl PoseidonCodeHash {
    fn new(bytes_in_field: usize) -> Self {
        Self { bytes_in_field }
    }
}

impl CodeHash for PoseidonCodeHash {
    fn hash_code(&self, code: &[u8]) -> Hash {
        use halo2_proofs::halo2curves::group::ff::PrimeField;
        use mpt_zktrie::hash::{MessageHashable, HASHABLE_DOMAIN_SPEC};
        let fls = (0..(code.len() / self.bytes_in_field))
            .map(|i| i * self.bytes_in_field)
            .map(|i| {
                let mut buf: [u8; 32] = [0; 32];
                U256::from_big_endian(&code[i..i + self.bytes_in_field]).to_little_endian(&mut buf);
                Fr::from_bytes(&buf).unwrap()
            });
        let msgs: Vec<_> = fls
            .chain(if code.len() % self.bytes_in_field == 0 {
                None
            } else {
                let last_code = &code[code.len() - code.len() % self.bytes_in_field..];
                // pad to bytes_in_field
                let mut last_buf = vec![0u8; self.bytes_in_field];
                last_buf.as_mut_slice()[..last_code.len()].copy_from_slice(last_code);
                let mut buf: [u8; 32] = [0; 32];
                U256::from_big_endian(&last_buf).to_little_endian(&mut buf);
                Some(Fr::from_bytes(&buf).unwrap())
            })
            .collect();

        let h = Fr::hash_msg(&msgs, Some(code.len() as u128 * HASHABLE_DOMAIN_SPEC));

        let mut buf: [u8; 32] = [0; 32];
        U256::from_little_endian(h.to_repr().as_ref()).to_big_endian(&mut buf);
        Hash::from_slice(&buf)
    }
}

#[test]
fn code_hashing() {
    let code_hasher = PoseidonCodeHash::new(31);
    let simple_byte: [u8; 1] = [0];
    assert_eq!(
        format!("{:?}", code_hasher.hash_code(&simple_byte)),
        "0x29f94b67ee4e78b2bb08da025f9943c1201a7af025a27600c2dd0a2e71c7cf8b"
    );

    let simple_byte: [u8; 2] = [0, 1];
    assert_eq!(
        format!("{:?}", code_hasher.hash_code(&simple_byte)),
        "0x1bd41d9cc3187305de467d841b6b999d1222260b7057cb6f63d2ae92c43a7322"
    );

    let byte32: [u8; 32] = [1; 32];
    assert_eq!(
        format!("{:?}", code_hasher.hash_code(&byte32)),
        "0x0b46d156183dffdbed8e6c6b0af139b95c058e735878ca7f4dca334e0ea8bd20"
    );

    let example = "6080604052600436106100a75760003560e01c80638431f5c1116100645780638431f5c114610177578063a93a4af91461018a578063c676ad291461019d578063e77772fe146101bd578063f887ea40146101dd578063f8c8765e146101fd57600080fd5b80633cb747bf146100ac57806354bbd59c146100e8578063575361b6146101215780636c07ea43146101365780637885ef0114610149578063797594b014610151575b600080fd5b3480156100b857600080fd5b506002546100cc906001600160a01b031681565b6040516001600160a01b03909116815260200160405180910390f35b3480156100f457600080fd5b506100cc610103366004610d51565b6001600160a01b039081166000908152600460205260409020541690565b61013461012f366004610dbe565b61021d565b005b610134610144366004610e39565b610269565b6101346102a8565b34801561015d57600080fd5b506000546100cc906201000090046001600160a01b031681565b610134610185366004610e6e565b610303565b610134610198366004610f06565b6106ad565b3480156101a957600080fd5b506100cc6101b8366004610d51565b6106c0565b3480156101c957600080fd5b506005546100cc906001600160a01b031681565b3480156101e957600080fd5b506001546100cc906001600160a01b031681565b34801561020957600080fd5b50610134610218366004610f4c565b61073b565b61026186868686868080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152508892506108b5915050565b505050505050565b6102a383338460005b6040519080825280601f01601f19166020018201604052801561029c576020820181803683370190505b50856108b5565b505050565b6002546001600160a01b031633146103015760405162461bcd60e51b81526020600482015260176024820152761bdb9b1e481b595cdcd95b99d95c8818d85b8818d85b1b604a1b60448201526064015b60405180910390fd5b565b6002546001600160a01b03163381146103585760405162461bcd60e51b81526020600482015260176024820152761bdb9b1e481b595cdcd95b99d95c8818d85b8818d85b1b604a1b60448201526064016102f8565b806001600160a01b0316636e296e456040518163ffffffff1660e01b8152600401602060405180830381865afa158015610396573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906103ba9190610fbe565b6000546201000090046001600160a01b0390811691161461041d5760405162461bcd60e51b815260206004820152601760248201527f6f6e6c792063616c6c20627920636f6e7465727061727400000000000000000060448201526064016102f8565b341561045f5760405162461bcd60e51b81526020600482015260116024820152706e6f6e7a65726f206d73672e76616c756560781b60448201526064016102f8565b6005546040516361e98ca160e01b81523060048201526001600160a01b038a8116602483015260009216906361e98ca190604401602060405180830381865afa1580156104b0573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906104d49190610fbe565b9050806001600160a01b0316886001600160a01b03161461052b5760405162461bcd60e51b81526020600482015260116024820152700d86440e8ded6cadc40dad2e6dac2e8c6d607b1b60448201526064016102f8565b506001600160a01b03878116600090815260046020526040902054606091829116610593576001600160a01b03898116600090815260046020526040902080546001600160a01b031916918c1691909117905561058a8585018661108a565b925090506105cd565b84848080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152509293505050505b6001600160a01b0389163b6105e6576105e6828b610b23565b6040516340c10f1960e01b81526001600160a01b038881166004830152602482018890528a16906340c10f1990604401600060405180830381600087803b15801561063057600080fd5b505af1158015610644573d6000803e3d6000fd5b50505050876001600160a01b0316896001600160a01b03168b6001600160a01b03167f165ba69f6ab40c50cade6f65431801e5f9c7d7830b7545391920db039133ba348a8a8660405161069993929190611146565b60405180910390a450505050505050505050565b6106ba8484846000610272565b50505050565b6005546040516361e98ca160e01b81523060048201526001600160a01b03838116602483015260009216906361e98ca190604401602060405180830381865afa158015610711573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906107359190610fbe565b92915050565b600054610100900460ff166107565760005460ff161561075a565b303b155b6107bd5760405162461bcd60e51b815260206004820152602e60248201527f496e697469616c697a61626c653a20636f6e747261637420697320616c72656160448201526d191e481a5b9a5d1a585b1a5e995960921b60648201526084016102f8565b600054610100900460ff161580156107df576000805461ffff19166101011790555b6001600160a01b03841661082b5760405162461bcd60e51b81526020600482015260136024820152727a65726f20726f75746572206164647265737360681b60448201526064016102f8565b610836858585610c29565b6001600160a01b0382166108815760405162461bcd60e51b81526020600482015260126024820152717a65726f20746f6b656e20666163746f727960701b60448201526064016102f8565b600580546001600160a01b0319166001600160a01b03841617905580156108ae576000805461ff00191690555b5050505050565b600083116108fc5760405162461bcd60e51b81526020600482015260146024820152731dda5d1a191c985dc81e995c9bc8185b5bdd5b9d60621b60448201526064016102f8565b60015433906001600160a01b031681141561092a578280602001905181019061092591906111a6565b935090505b6001600160a01b0380871660009081526004602052604090205416806109925760405162461bcd60e51b815260206004820152601960248201527f6e6f20636f72726573706f6e64696e67206c3120746f6b656e0000000000000060448201526064016102f8565b604051632770a7eb60e21b81526001600160a01b03838116600483015260248201879052881690639dc29fac90604401600060405180830381600087803b1580156109dc57600080fd5b505af11580156109f0573d6000803e3d6000fd5b5050505060006384bd13b060e01b8289858a8a8a604051602401610a1996959493929190611201565b60408051601f198184030181529181526020820180516001600160e01b03166001600160e01b031990941693909317909252600254600054925163b2267a7b60e01b81529193506001600160a01b039081169263b2267a7b923492610a8e926201000090041690839087908b90600401611250565b6000604051808303818588803b158015610aa757600080fd5b505af1158015610abb573d6000803e3d6000fd5b5050505050826001600160a01b0316886001600160a01b0316836001600160a01b03167fd8d3a3f4ab95694bef40475997598bcf8acd3ed9617a4c1013795429414c27e88a8a8a604051610b1193929190611146565b60405180910390a45050505050505050565b600554604051637bdbcbbf60e01b81523060048201526001600160a01b0383811660248301526000921690637bdbcbbf906044016020604051808303816000875af1158015610b76573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610b9a9190610fbe565b9050600080600085806020019051810190610bb591906112a8565b925092509250836001600160a01b031663c820f146838584308a6040518663ffffffff1660e01b8152600401610bef959493929190611326565b600060405180830381600087803b158015610c0957600080fd5b505af1158015610c1d573d6000803e3d6000fd5b50505050505050505050565b6001600160a01b038316610c7f5760405162461bcd60e51b815260206004820152601860248201527f7a65726f20636f756e746572706172742061646472657373000000000000000060448201526064016102f8565b6001600160a01b038116610cce5760405162461bcd60e51b81526020600482015260166024820152757a65726f206d657373656e676572206164647265737360501b60448201526064016102f8565b6000805462010000600160b01b031916620100006001600160a01b038681169190910291909117909155600280546001600160a01b031916838316179055821615610d2f57600180546001600160a01b0319166001600160a01b0384161790555b5050600160035550565b6001600160a01b0381168114610d4e57600080fd5b50565b600060208284031215610d6357600080fd5b8135610d6e81610d39565b9392505050565b60008083601f840112610d8757600080fd5b50813567ffffffffffffffff811115610d9f57600080fd5b602083019150836020828501011115610db757600080fd5b9250929050565b60008060008060008060a08789031215610dd757600080fd5b8635610de281610d39565b95506020870135610df281610d39565b945060408701359350606087013567ffffffffffffffff811115610e1557600080fd5b610e2189828a01610d75565b979a9699509497949695608090950135949350505050565b600080600060608486031215610e4e57600080fd5b8335610e5981610d39565b95602085013595506040909401359392505050565b600080600080600080600060c0888a031215610e8957600080fd5b8735610e9481610d39565b96506020880135610ea481610d39565b95506040880135610eb481610d39565b94506060880135610ec481610d39565b93506080880135925060a088013567ffffffffffffffff811115610ee757600080fd5b610ef38a828b01610d75565b989b979a50959850939692959293505050565b60008060008060808587031215610f1c57600080fd5b8435610f2781610d39565b93506020850135610f3781610d39565b93969395505050506040820135916060013590565b60008060008060808587031215610f6257600080fd5b8435610f6d81610d39565b93506020850135610f7d81610d39565b92506040850135610f8d81610d39565b91506060850135610f9d81610d39565b939692955090935050565b634e487b7160e01b600052604160045260246000fd5b600060208284031215610fd057600080fd5b8151610d6e81610d39565b604051601f8201601f1916810167ffffffffffffffff8111828210171561100457611004610fa8565b604052919050565b600067ffffffffffffffff82111561102657611026610fa8565b50601f01601f191660200190565b600082601f83011261104557600080fd5b81356110586110538261100c565b610fdb565b81815284602083860101111561106d57600080fd5b816020850160208301376000918101602001919091529392505050565b6000806040838503121561109d57600080fd5b823567ffffffffffffffff808211156110b557600080fd5b6110c186838701611034565b935060208501359150808211156110d757600080fd5b506110e485828601611034565b9150509250929050565b60005b838110156111095781810151838201526020016110f1565b838111156106ba5750506000910152565b600081518084526111328160208601602086016110ee565b601f01601f19169290920160200192915050565b60018060a01b038416815282602082015260606040820152600061116d606083018461111a565b95945050505050565b60006111846110538461100c565b905082815283838301111561119857600080fd5b610d6e8360208301846110ee565b600080604083850312156111b957600080fd5b82516111c481610d39565b602084015190925067ffffffffffffffff8111156111e157600080fd5b8301601f810185136111f257600080fd5b6110e485825160208401611176565b6001600160a01b03878116825286811660208301528581166040830152841660608201526080810183905260c060a082018190526000906112449083018461111a565b98975050505050505050565b60018060a01b0385168152836020820152608060408201526000611277608083018561111a565b905082606083015295945050505050565b600082601f83011261129957600080fd5b610d6e83835160208501611176565b6000806000606084860312156112bd57600080fd5b835167ffffffffffffffff808211156112d557600080fd5b6112e187838801611288565b945060208601519150808211156112f757600080fd5b5061130486828701611288565b925050604084015160ff8116811461131b57600080fd5b809150509250925092565b60a08152600061133960a083018861111a565b828103602084015261134b818861111a565b60ff96909616604084015250506001600160a01b03928316606082015291166080909101529291505056fea2646970667358221220ecd187c94a71cff6b791b98b05df232b66ff286e240691cae5a392562812230864736f6c634300080a0033";
    let bytes = hex::decode(example).unwrap();

    assert_eq!(
        format!("{:?}", code_hasher.hash_code(&bytes)),
        "0x26f706f949ff4faad54ee72308e9d30ece46e37cf8b9968bdb274e750a264937"
    );
}
*/
/*
fn get_account_deployed_codehash(
    execution_result: &ExecutionResult,
) -> Result<eth_types::H256, anyhow::Error> {
    let created_acc = execution_result
        .account_created
        .as_ref()
        .expect("called when field existed")
        .address
        .as_ref()
        .unwrap();
    for state in &execution_result.account_after {
        if Some(created_acc) == state.address.as_ref() {
            return state.code_hash.ok_or_else(|| anyhow!("empty code hash"));
        }
    }
    Err(anyhow!("can not find created address in account after"))
}
fn get_account_created_codehash(step: &ExecStep) -> Result<eth_types::H256, anyhow::Error> {
    let extra_data = step
        .extra_data
        .as_ref()
        .ok_or_else(|| anyhow!("no extra data in create context"))?;
    let proof_list = extra_data
        .proof_list
        .as_ref()
        .expect("should has proof list");
    if proof_list.len() < 2 {
        Err(anyhow!("wrong fields in create context"))
    } else {
        proof_list[1]
            .code_hash
            .ok_or_else(|| anyhow!("empty code hash in final state"))
    }
}
*/
fn trace_code(cdb: &mut CodeDB, step: &ExecStep, sdb: &StateDB, code: Bytes, stack_pos: usize) {
    let stack = step
        .stack
        .as_ref()
        .expect("should have stack in call context");
    let addr = stack[stack.len() - stack_pos - 1].to_address(); //stack N-stack_pos

    let hash = cdb.insert(code.to_vec());

    // sanity check
    let (existed, data) = sdb.get_account(&addr);
    if existed && !data.code_size.is_zero() {
        assert_eq!(
            hash, data.code_hash,
            "invalid codehash for existed account {addr:?}, {data:?}"
        );
    };
}
pub fn build_codedb(sdb: &StateDB, blocks: &[BlockTrace]) -> Result<CodeDB, anyhow::Error> {
    let mut cdb = CodeDB::new();

    for block in blocks.iter().rev() {
        // notice empty codehash always kept as keccak256(nil)
        cdb.insert(Vec::new());

        for (er_idx, execution_result) in block.execution_results.iter().enumerate() {
            if let Some(bytecode) = &execution_result.byte_code {
                let _hash = cdb.insert(decode_bytecode(bytecode)?.to_vec());

                if execution_result.account_created.is_none() {
                    //assert_eq!(Some(hash), execution_result.code_hash);
                }
            }

            for step in execution_result.exec_steps.iter().rev() {
                if let Some(data) = &step.extra_data {
                    match step.op {
                        OpcodeId::CALL
                        | OpcodeId::CALLCODE
                        | OpcodeId::DELEGATECALL
                        | OpcodeId::STATICCALL => {
                            let code_idx = if block.transactions[er_idx].to.is_none() {
                                0
                            } else {
                                1
                            };
                            let callee_code = data.get_code_at(code_idx);
                            if callee_code.is_none() {
                                log::error!("cannot get code of call: {:?}", step);
                            }
                            trace_code(&mut cdb, step, sdb, callee_code.unwrap(), 1);
                        }
                        OpcodeId::CREATE | OpcodeId::CREATE2 => {
                            // notice we do not need to insert code for CREATE,
                            // bustmapping do this job
                        }
                        OpcodeId::EXTCODESIZE | OpcodeId::EXTCODECOPY => {
                            let code = data.get_code_at(0);
                            if code.is_none() {
                                log::error!("cannot get code of ext: {:?}", step);
                            }
                            trace_code(&mut cdb, step, sdb, code.unwrap(), 0);
                        }

                        _ => {}
                    }
                }
            }
        }
    }

    Ok(cdb)
}

/*
pub fn trace_proof(sdb: &mut StateDB, proof: Option<AccountProofWrapper>) {
    // `to` may be empty
    if proof.is_none() {
        return;
    }
    let proof = proof.unwrap();

    let (found, acc) = sdb.get_account(&proof.address.unwrap());
    let mut storage = match found {
        true => acc.storage.clone(),
        false => HashMap::new(),
    };

    if let Some(s) = &proof.storage {
        log::trace!(
            "trace_proof ({:?}, {:?}) => {:?}",
            &proof.address.unwrap(),
            s.key.unwrap(),
            s.value.unwrap()
        );
        storage.insert(s.key.unwrap(), s.value.unwrap());
    }

    sdb.set_account(
        &proof.address.unwrap(),
        Account {
            nonce: proof.nonce.unwrap().into(),
            balance: proof.balance.unwrap(),
            storage,
            code_hash: proof.code_hash.unwrap(),
        },
    )
}
*/
