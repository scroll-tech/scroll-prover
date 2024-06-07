use anyhow::Result;
use reqwest::Url;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ChunkInfo {
    pub index: i64,
    pub start_block_number: i64,
    pub end_block_number: i64,
}

#[derive(Debug, Deserialize)]
struct ChunksResponse {
    batch_index: usize,
    chunks: Option<Vec<ChunkInfo>>,
}

pub struct Client {
    id: String,
    chunks_url: String,
}

impl Client {
    pub fn new(id: &str, chunks_url: &str) -> Self {
        Self {
            id: id.to_string(),
            chunks_url: chunks_url.to_string(),
        }
    }

    pub async fn get_chunk_info_by_batch_index(
        &self,
        batch_index: i64,
    ) -> Result<Option<Vec<ChunkInfo>>> {
        log::info!(
            "{}: requesting block traces of batch-{}",
            self.id,
            batch_index
        );

        let url = Url::parse_with_params(
            &self.chunks_url,
            &[("batch_index", batch_index.to_string())],
        )?;

        let resp: String = reqwest::get(url).await?.text().await?;
        log::debug!("{}: rollupscan response = {}", self.id, resp);
        let resp: ChunksResponse = serde_json::from_str(&resp)?;
        log::info!(
            "{}: handling batch {}, chunk size {}",
            self.id,
            resp.batch_index,
            resp.chunks.as_ref().unwrap().len()
        );

        Ok(resp.chunks)
    }
}
