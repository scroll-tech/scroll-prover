use anyhow::Result;
use ethers_providers::{Http, Provider};
use prover::BlockTrace;

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

    pub async fn get_block_trace_by_num(&self, block_num: i64) -> Result<BlockTrace> {
        log::info!("{}: requesting trace of block {}", self.id, block_num);

        let trace = self
            .provider
            .request(
                "scroll_getBlockTraceByNumberOrHash",
                [format!("{block_num:#x}")],
            )
            .await?;

        Ok(trace)
    }
}
