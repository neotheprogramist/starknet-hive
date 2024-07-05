use crate::{
    jsonrpc::{HttpTransport, JsonRpcClient},
    provider::{Provider, ProviderError},
};

use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum BlockNumberError {
    #[error("Error getting response text")]
    ProviderError(#[from] ProviderError),
}

pub async fn block_number(url: Url) -> Result<u64, BlockNumberError> {
    let rpc_client = JsonRpcClient::new(HttpTransport::new(url.clone()));

    let block_number = rpc_client.block_number().await?;

    Ok(block_number)
}
