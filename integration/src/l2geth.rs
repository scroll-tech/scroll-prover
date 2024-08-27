use anyhow::Result;
use ethers_providers::{Http, Middleware, Provider};
use prover::BlockTrace;
use serde::Serialize;

pub struct Client {
    id: String,
    provider: Provider<Http>,
}

impl Client {
    pub fn new(id: &str, api_url: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(api_url)?;

        Ok(Self {
            id: id.to_string(),
            provider,
        })
    }

    pub async fn get_block_number(&self) -> Result<u64> {
        Ok(self.provider.get_block_number().await?.as_u64())
    }
    pub async fn get_txbytx_trace_by_num(&self, block_num: i64) -> Result<Vec<BlockTrace>> {
        let params =
            serde_json::json!([format!("{block_num:#x}"), {"StorageProofFormat": "legacy"}]);
        let trace = self
            .provider
            .request("scroll_getTxByTxBlockTrace", params)
            .await?;
        Ok(trace)
    }

    // when override_curie == true,
    //   we will force curie hard fork when tracing
    pub async fn get_block_trace_by_num(
        &self,
        block_num: i64,
        override_curie: bool,
    ) -> Result<BlockTrace> {
        log::info!("{}: requesting trace of block {}", self.id, block_num);

        let params = if override_curie {
            // curl -s -H 'Content-Type: application/json' -X POST --data
            // '{"jsonrpc":"2.0","method":"scroll_getBlockTraceByNumberOrHash",
            // "params": ["0x485490", {"overrides": {"curieBlock":1}}], "id": 99}'
            // 127.0.0.1:8545
            #[derive(Serialize)]
            struct ChainConfig {
                #[serde(rename = "curieBlock")]
                curie_block: usize,
            }
            #[derive(Serialize)]
            struct TraceConfig {
                overrides: ChainConfig,
            }
            let override_param = TraceConfig {
                overrides: ChainConfig {
                    curie_block: 1, // any small value could be ok
                },
            };
            serde_json::json!([format!("{block_num:#x}"), override_param])
        } else {
            serde_json::json!([format!("{block_num:#x}"), {"StorageProofFormat": "legacy"}])
        };
        let trace = self
            .provider
            .request("scroll_getBlockTraceByNumberOrHash", params)
            .await?;
        Ok(trace)
    }
}
