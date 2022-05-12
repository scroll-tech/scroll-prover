use eth_types::evm_types::{Gas, GasCost, Memory, OpcodeId, ProgramCounter, Stack, Storage};
use eth_types::{
    fix_geth_trace_memory_size, Block, GethExecStep, GethExecTrace, Hash, Transaction, Word, H256,
};
use ethers_core::types::{Address, Bytes, U256, U64};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

/// BlockResultWrapper is the payload from Scroll.
#[derive(Deserialize, Serialize, Default, Debug)]
pub struct BlockResultWrapper {
    pub id: u64,
    #[serde(rename = "blockTraces")]
    pub block_result: BlockResult,
}

/// ZkProof is the payload to Scroll.
#[derive(Serialize, Debug)]
pub struct ZkProof {
    pub id: u64,
    #[serde(rename = "evmTranscript")]
    pub evm_transcript: Vec<u8>,
    #[serde(rename = "stateTranscript")]
    pub state_transcript: Vec<u8>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct BlockResult {
    #[serde(rename = "blockTrace")]
    pub block_trace: BlockTrace,
    #[serde(rename = "executionResults")]
    pub execution_results: Vec<ExecutionResult>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct BlockTrace {
    pub number: U64,
    pub hash: Hash,
    pub time: u64,
    pub coinbase: AccountProofWrapper,
    pub difficulty: U256,
    pub transactions: Vec<TransactionTrace>,
    #[serde(rename = "baseFee")]
    pub base_fee: Option<U256>,
    #[serde(rename = "gasLimit")]
    pub gas_limit: u64,
}

pub type EthBlock = Block<Transaction>;

impl BlockTrace {
    pub fn to_eth_block(&self) -> EthBlock {
        let mut transactions = Vec::new();
        for (tx_idx, tx_trace) in self.transactions.iter().enumerate() {
            let tx_idx = Some(U64::from(tx_idx));
            let block_hash = Some(self.hash);
            let block_number = Some(self.number);
            let tx = tx_trace.to_eth_tx(block_hash, block_number, tx_idx);
            transactions.push(tx)
        }
        EthBlock {
            hash: Some(self.hash),
            parent_hash: Default::default(),
            uncles_hash: Default::default(),
            author: self.coinbase.address.unwrap(),
            state_root: Default::default(),
            transactions_root: Default::default(),
            receipts_root: Default::default(),
            number: Some(self.number),
            gas_used: Default::default(),
            gas_limit: U256::from(self.gas_limit),
            extra_data: Default::default(),
            logs_bloom: None,
            timestamp: U256::from(self.time),
            difficulty: self.difficulty,
            total_difficulty: None,
            seal_fields: vec![],
            uncles: vec![],
            transactions,
            size: None,
            mix_hash: None,
            nonce: None,
            base_fee_per_gas: self.base_fee,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct TransactionTrace {
    #[serde(rename = "type")]
    pub type_: u8,
    pub nonce: u64,
    pub gas: u64,
    #[serde(rename = "gasPrice")]
    pub gas_price: U256,
    pub from: Address,
    pub to: Option<Address>,
    #[serde(rename = "chainId")]
    pub chain_id: U256,
    pub value: U256,
    pub data: Bytes,
    #[serde(rename = "isCreate")]
    pub is_create: bool,
    pub v: U64,
    pub r: U256,
    pub s: U256,
}

impl TransactionTrace {
    pub fn to_eth_tx(
        &self,
        block_hash: Option<H256>,
        block_number: Option<U64>,
        transaction_index: Option<U64>,
    ) -> Transaction {
        Transaction {
            hash: Default::default(),
            nonce: U256::from(self.nonce),
            block_hash,
            block_number,
            transaction_index,
            from: self.from,
            to: self.to,
            value: self.value,
            gas_price: Some(self.gas_price),
            gas: U256::from(self.gas),
            input: self.data.clone(),
            v: self.v,
            r: self.r,
            s: self.s,
            transaction_type: None,
            access_list: None,
            max_priority_fee_per_gas: None,
            max_fee_per_gas: None,
            chain_id: Some(self.chain_id),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ExecutionResult {
    pub gas: u64,
    pub failed: bool,
    #[serde(rename = "returnValue", default)]
    pub return_value: String,
    #[serde(rename = "sender")]
    pub sender: Option<AccountProofWrapper>,
    #[serde(rename = "codeHash")]
    pub code_hash: Option<Hash>,
    #[serde(rename = "byteCode")]
    pub byte_code: Option<String>,
    #[serde(rename = "structLogs")]
    pub exec_steps: Vec<ExecStep>,
}

impl ExecutionResult {
    pub fn to_geth_exec_trace(&self) -> GethExecTrace {
        let mut struct_logs = Vec::new();
        for exec_step in &self.exec_steps {
            let step = exec_step.to_geth_exec_step();
            struct_logs.push(step)
        }
        fix_geth_trace_memory_size(&mut struct_logs);
        GethExecTrace {
            gas: Gas(self.gas),
            failed: self.failed,
            return_value: self.return_value.clone(),
            struct_logs,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ExecStep {
    pub pc: u64,
    pub op: OpcodeId,
    pub gas: u64,
    #[serde(rename = "gasCost")]
    pub gas_cost: u64,
    #[serde(default)]
    pub refund: u64,
    pub depth: isize,
    pub error: Option<String>,
    pub stack: Option<Vec<Word>>,
    pub memory: Option<Vec<Word>>,
    pub storage: Option<HashMap<Word, Word>>,
    #[serde(rename = "extraData")]
    pub extra_data: Option<ExtraData>,
}

impl ExecStep {
    #[allow(dead_code)]
    fn to_geth_exec_step(&self) -> GethExecStep {
        let stack = if let Some(stack) = self.stack.clone() {
            Stack::from(stack)
        } else {
            Stack::new()
        };

        let memory = if let Some(memory) = self.memory.clone() {
            Memory::from(memory)
        } else {
            Memory::new()
        };

        let storage = if let Some(storage) = self.storage.clone() {
            Storage::from(storage)
        } else {
            Storage::empty()
        };

        GethExecStep {
            pc: ProgramCounter(self.pc as usize),
            // FIXME
            op: self.op,
            gas: Gas(self.gas),
            gas_cost: GasCost(self.gas_cost),
            refund: Gas(self.refund),
            depth: self.depth as u16,
            error: self.error.clone(),
            stack,
            memory,
            storage,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExtraData {
    #[serde(rename = "codeList")]
    pub code_list: Option<Vec<Bytes>>,
    #[serde(rename = "proofList")]
    pub proof_list: Option<Vec<AccountProofWrapper>>,
}

impl ExtraData {
    pub fn get_code_at(&self, i: usize) -> Bytes {
        self.code_list.as_ref().unwrap().get(i).cloned().unwrap()
    }

    pub fn get_proof_at(&self, i: usize) -> AccountProofWrapper {
        self.proof_list.as_ref().unwrap().get(i).cloned().unwrap()
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct AccountProofWrapper {
    pub address: Option<Address>,
    pub nonce: Option<u64>,
    pub balance: Option<U256>,
    #[serde(rename = "codeHash")]
    pub code_hash: Option<H256>,
    pub proof: Option<Vec<Bytes>>,
    pub storage: Option<StorageProofWrapper>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StorageProofWrapper {
    pub key: Option<U256>,
    pub value: Option<U256>,
    pub proof: Option<Vec<Bytes>>,
}

#[cfg(any(feature = "test", test))]
pub mod test {
    use crate::eth::{AccountProofWrapper, BlockResult, BlockResultWrapper};
    use crate::roller::{Msg, Type};
    use eth_types::{Address, H256, U256};

    #[test]
    fn codec_traces() {
        let msg = mock_trace_msg();
        let msg_str = serde_json::to_string(&msg).unwrap();

        let decoded_msg = serde_json::from_str::<Msg>(&msg_str).unwrap();
        serde_json::from_slice::<BlockResultWrapper>(&decoded_msg.payload).unwrap();
        assert_eq!(msg, decoded_msg);
    }

    pub fn mock_trace_msg() -> Msg {
        let block_result = BlockResultWrapper {
            block_result: mock_block_result(),
            ..Default::default()
        };
        let block_result_json = serde_json::to_vec(&block_result).unwrap();
        Msg {
            msg_type: Type::EvmTrace,
            payload: block_result_json,
        }
    }

    pub fn mock_block_result() -> BlockResult {
        let mut block_result = BlockResult::default();
        block_result.block_trace.coinbase = AccountProofWrapper {
            address: Some(Address::from_slice("12345678901234567890".as_bytes())),
            nonce: Some(100),
            balance: Some(U256::from(100)),
            code_hash: Some(H256::zero()),
            ..Default::default()
        };
        block_result
    }
}
