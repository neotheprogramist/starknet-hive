use crate::{
    account::create_mint_deploy::create_mint_deploy,
    errors::errors::RunnerError,
    jsonrpc::{HttpTransport, JsonRpcClient},
    provider::ProviderError,
    utilities::{declare_contract_v3, deploy_contract_v3},
    ConnectedAccount, ExecutionEncoding, SingleOwnerAccount,
};
use rand::Rng;
use starknet_core::types::Felt;
use starknet_signers::{LocalWallet, SigningKey};
use starknet_types_core::felt::FromStrError;
use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum DeployError {
    #[error("Error getting response text")]
    CreateAccountError(String),

    #[error("Error getting response text")]
    ProviderError(#[from] ProviderError),

    #[error("Error parsing hex string")]
    FromStrError(#[from] FromStrError),

    #[error("Runner error")]
    RunnerError(#[from] RunnerError),
}

pub async fn deploy(url: Url, chain_id: String) -> Result<Felt, DeployError> {
    let rpc_client = JsonRpcClient::new(HttpTransport::new(url.clone()));

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(Felt::from_hex(
        "0x71d7bb07b9a64f6f78ac4c816aff4da9",
    )?));

    let account = SingleOwnerAccount::new(
        rpc_client.clone(),
        signer,
        Felt::from_hex("0x64b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691")?,
        Felt::from_hex(&chain_id)?,
        ExecutionEncoding::New,
    );

    let class_hash = declare_contract_v3(
        &account,
        "../target/dev/example_HelloStarknet.contract_class.json",
        "../target/dev/example_HelloStarknet.compiled_contract_class.json",
    )
    .await?;

    let random_loop_count = rand::thread_rng().gen_range(10..=30);

    for _ in 0..random_loop_count {
        deploy_contract_v3(&account, class_hash).await;
    }

    let nonce = account.get_nonce().await?;

    assert_eq!(
        nonce,
        Felt::from_dec_str(&(random_loop_count + 1).to_string())?,
    );
    Ok(nonce)
}
