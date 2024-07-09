use async_trait::async_trait;
use auto_impl::auto_impl;
use serde::{de::DeserializeOwned, Serialize};
use std::error::Error;

use crate::jsonrpc::{JsonRpcMethod, JsonRpcResponse};

mod http;
pub use http::{HttpTransport, HttpTransportError};

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[auto_impl(&, Box, Arc)]
pub trait JsonRpcTransport {
    type Error: Error + Send + Sync;

    async fn send_request<P, R>(
        &self,
        method: JsonRpcMethod,
        params: P,
    ) -> Result<JsonRpcResponse<R>, Self::Error>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned;
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[auto_impl(&, Box, Arc)]
pub trait JsonRpcTransportQueryParams {
    type Error: Error + Send + Sync;

    async fn send_request_query_params<P>(
        &self,
        method: JsonRpcMethod,
        params: P,
    ) -> Result<serde_json::Value, Self::Error>
    where
        P: Serialize + Send + Sync;
}
