use starknet_types_core::felt::Felt;
use starknet_types_rpc::{
    v0_7_1::{BlockId, BlockTag, TxnHash},
    BroadcastedDeployAccountTxn, BroadcastedTxn, ContractAndTxnHash, DeployAccountTxn,
    DeployAccountTxnV1, DeployAccountTxnV3, FeeEstimate, SimulateTransactionsResult,
};

use crate::utils::v7::{
    self,
    accounts::{
        creation::{create::AccountType, structs::GenerateAccountResponse},
        errors::CreationError,
    },
    providers::{
        jsonrpc::{HttpTransport, JsonRpcClient},
        provider::Provider,
    },
};

use super::{
    helpers::{
        get_contract_address, get_deployment_request, get_deployment_result,
        get_estimate_fee_deployment_result, simulate_get_deployment_result,
    },
    structs::WaitForTx,
};

pub enum DeployAccountVersion {
    V1,
    V3,
}

pub async fn deploy_account(
    provider: &JsonRpcClient<HttpTransport>,
    chain_id: Felt,
    wait_config: WaitForTx,
    account_data: GenerateAccountResponse,
    version: DeployAccountVersion,
) -> Result<TxnHash<Felt>, CreationError> {
    if account_data.deployed {
        tracing::warn!("Account already deployed!");
        return Ok(Felt::ZERO);
    }
    let public_key = account_data.signing_key.verifying_key();
    let address = match account_data.account_type {
        AccountType::Oz => get_contract_address(
            account_data.salt,
            account_data.class_hash,
            &[public_key.scalar(), Felt::ZERO],
            Felt::ZERO,
        ),
    };

    let result = if provider
        .get_class_hash_at(BlockId::Tag(BlockTag::Pending), address)
        .await
        .is_ok()
    {
        Felt::ZERO
    } else {
        get_deployment_result(
            provider,
            account_data.account_type,
            account_data.class_hash,
            account_data.signing_key,
            account_data.salt,
            chain_id,
            Some(account_data.max_fee),
            wait_config,
            version,
        )
        .await?
    };
    Ok(result)
}

pub async fn simulate_deploy_account(
    provider: &JsonRpcClient<HttpTransport>,
    chain_id: Felt,
    wait_config: WaitForTx,
    account_data: GenerateAccountResponse,
    skip_validate: bool,
    skip_fee_charge: bool,
    version: DeployAccountVersion,
) -> Result<
    SimulateTransactionsResult<Felt>,
    crate::utils::v7::accounts::factory::AccountFactoryError<v7::signers::local_wallet::SignError>,
> {
    simulate_get_deployment_result(
        provider,
        account_data.account_type,
        account_data.class_hash,
        account_data.signing_key,
        account_data.salt,
        chain_id,
        Some(account_data.max_fee),
        wait_config,
        skip_validate,
        skip_fee_charge,
        version,
    )
    .await
}

pub async fn estimate_fee_deploy_account(
    provider: &JsonRpcClient<HttpTransport>,
    chain_id: Felt,
    wait_config: WaitForTx,
    account_data: GenerateAccountResponse,
    skip_validate: bool,
    version: DeployAccountVersion,
) -> Result<
    FeeEstimate<Felt>,
    crate::utils::v7::accounts::factory::AccountFactoryError<v7::signers::local_wallet::SignError>,
> {
    get_estimate_fee_deployment_result(
        provider,
        account_data.account_type,
        account_data.class_hash,
        account_data.signing_key,
        account_data.salt,
        chain_id,
        Some(account_data.max_fee),
        wait_config,
        skip_validate,
        version,
    )
    .await
}

pub async fn get_deploy_account_request(
    provider: &JsonRpcClient<HttpTransport>,
    chain_id: Felt,
    wait_config: WaitForTx,
    account_data: GenerateAccountResponse,
    version: DeployAccountVersion,
) -> Result<DeployAccountTxn<Felt>, CreationError> {
    get_deployment_request(
        provider,
        account_data.account_type,
        account_data.class_hash,
        account_data.signing_key,
        account_data.salt,
        chain_id,
        Some(account_data.max_fee),
        wait_config,
        version,
    )
    .await
}

pub async fn deploy_account_v1_from_request(
    provider: &JsonRpcClient<HttpTransport>,
    tx_request: DeployAccountTxnV1<Felt>,
) -> Result<ContractAndTxnHash<Felt>, CreationError> {
    provider
        .add_deploy_account_transaction(BroadcastedTxn::DeployAccount(
            BroadcastedDeployAccountTxn::V1(tx_request),
        ))
        .await
        .map_err(CreationError::from)
}

pub async fn deploy_account_v3_from_request(
    provider: &JsonRpcClient<HttpTransport>,
    tx_request: DeployAccountTxnV3<Felt>,
) -> Result<ContractAndTxnHash<Felt>, CreationError> {
    provider
        .add_deploy_account_transaction(BroadcastedTxn::DeployAccount(
            BroadcastedDeployAccountTxn::V3(tx_request),
        ))
        .await
        .map_err(CreationError::from)
}
