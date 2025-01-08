use crate::utils::v7::{
    accounts::{
        errors::CreationError,
        factory::{open_zeppelin::OpenZeppelinAccountFactory, AccountDeploymentV3, AccountFactory},
    },
    providers::{
        jsonrpc::{HttpTransport, JsonRpcClient, StarknetError},
        provider::{Provider, ProviderError},
    },
    signers::{key_pair::SigningKey, local_wallet::LocalWallet},
};
use rand::{rngs::OsRng, RngCore};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::v0_7_1::{BlockId, BlockTag, FeeEstimate};

use super::{create::AccountType, structs::GenerateAccountResponse};

pub const OZ_CLASS_HASH: &str = "0x61dac032f228abef9c6626f995015233097ae253a7f72d68552db02f2971b8f";

pub fn extract_or_generate_salt(salt: Option<Felt>) -> Felt {
    salt.unwrap_or(Felt::from(OsRng.next_u64()))
}

pub async fn check_class_hash_exists(
    provider: &JsonRpcClient<HttpTransport>,
    class_hash: Felt,
) -> Result<(), CreationError> {
    match provider
        .get_class(BlockId::Tag(BlockTag::Latest), class_hash)
        .await
    {
        Ok(_) => Ok(()),
        Err(err) => match err {
            ProviderError::StarknetError(StarknetError::ClassHashNotFound) => {
                Err(CreationError::ClassHashNotFound(class_hash))
            }
            _ => Err(CreationError::ProviderError(err)),
        },
    }
}

pub async fn generate_account(
    provider: &JsonRpcClient<HttpTransport>,
    salt: Felt,
    class_hash: Felt,
    account_type: &AccountType,
) -> Result<GenerateAccountResponse, CreationError> {
    let chain_id = provider.chain_id().await?;
    let signing_key = SigningKey::from_random();
    let signer = LocalWallet::from_signing_key(signing_key);

    let (address, fee_estimate) = match account_type {
        AccountType::Oz => {
            let factory = OpenZeppelinAccountFactory::new(class_hash, chain_id, signer, provider)
                .await
                .unwrap();
            get_address_and_deployment_fee(factory, salt).await?
        }
    };
    let account_response = GenerateAccountResponse {
        signing_key,
        address,
        deployed: false,
        account_type: AccountType::Oz,
        class_hash,
        salt,
        max_fee: Felt::from_dec_str(&fee_estimate.overall_fee.to_string()).unwrap(),
    };
    Ok(account_response)
}

pub async fn get_chain_id(provider: &JsonRpcClient<HttpTransport>) -> Result<Felt, ProviderError> {
    provider.chain_id().await
}

async fn get_address_and_deployment_fee<T>(
    account_factory: T,
    salt: Felt,
) -> Result<(Felt, FeeEstimate<Felt>), CreationError>
where
    T: AccountFactory + Sync,
{
    let deployment = account_factory.deploy_v3(salt);
    Ok((deployment.address(), get_deployment_fee(&deployment).await?))
}

async fn get_deployment_fee<'a, T>(
    account_deployment: &AccountDeploymentV3<'a, T>,
) -> Result<FeeEstimate<Felt>, String>
where
    T: AccountFactory + Sync,
{
    let fee_estimate = account_deployment.estimate_fee().await;

    match fee_estimate {
        Ok(fee_estimate) => Ok(fee_estimate),
        Err(err) => Err(format!(
            "Failed to estimate account deployment fee. Reason: {}",
            err
        )),
    }
}
