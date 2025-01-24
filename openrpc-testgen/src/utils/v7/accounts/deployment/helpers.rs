use crypto_utils::curve::signer::compute_hash_on_elements;
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{DeployAccountTxn, FeeEstimate, SimulateTransactionsResult};

use crate::utils::v7::{
    self,
    accounts::{
        account::normalize_address,
        creation::create::AccountType,
        errors::CreationError,
        factory::{open_zeppelin::OpenZeppelinAccountFactory, AccountFactory, AccountFactoryError},
    },
    providers::jsonrpc::{HttpTransport, JsonRpcClient},
    signers::{key_pair::SigningKey, local_wallet::LocalWallet},
};

use super::{deploy::DeployAccountVersion, structs::WaitForTx};

// Cairo string of "STARKNET_CONTRACT_ADDRESS"
const CONTRACT_ADDRESS_PREFIX: Felt = Felt::from_raw([
    533439743893157637,
    8635008616843941496,
    17289941567720117366,
    3829237882463328880,
]);

/// Computes the target contract address of a "native" contract deployment. Use
/// `get_udc_deployed_address` instead if you want to compute the target address for deployments
/// through the Universal Deployer Contract.
pub fn get_contract_address(
    salt: Felt,
    class_hash: Felt,
    constructor_calldata: &[Felt],
    deployer_address: Felt,
) -> Felt {
    normalize_address(compute_hash_on_elements(&[
        CONTRACT_ADDRESS_PREFIX,
        deployer_address,
        salt,
        class_hash,
        compute_hash_on_elements(constructor_calldata),
    ]))
}

#[allow(clippy::too_many_arguments)]
pub async fn get_estimate_fee_deployment_result(
    provider: &JsonRpcClient<HttpTransport>,
    account_type: AccountType,
    class_hash: Felt,
    signing_key: SigningKey,
    salt: Felt,
    chain_id: Felt,
    max_fee: Option<Felt>,
    wait_config: WaitForTx,
    skip_validate: bool,
    version: DeployAccountVersion,
) -> Result<
    FeeEstimate<Felt>,
    crate::utils::v7::accounts::factory::AccountFactoryError<v7::signers::local_wallet::SignError>,
> {
    match account_type {
        AccountType::Oz => {
            estimate_fee_deploy_oz_account(
                provider,
                class_hash,
                signing_key,
                salt,
                chain_id,
                max_fee,
                wait_config,
                skip_validate,
                version,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn simulate_get_deployment_result(
    provider: &JsonRpcClient<HttpTransport>,
    account_type: AccountType,
    class_hash: Felt,
    signing_key: SigningKey,
    salt: Felt,
    chain_id: Felt,
    max_fee: Option<Felt>,
    wait_config: WaitForTx,
    skip_validate: bool,
    skip_fee_charge: bool,
    version: DeployAccountVersion,
) -> Result<
    SimulateTransactionsResult<Felt>,
    crate::utils::v7::accounts::factory::AccountFactoryError<v7::signers::local_wallet::SignError>,
> {
    match account_type {
        AccountType::Oz => {
            simulate_deploy_oz_account(
                provider,
                class_hash,
                signing_key,
                salt,
                chain_id,
                max_fee,
                wait_config,
                skip_validate,
                skip_fee_charge,
                version,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn get_deployment_result(
    provider: &JsonRpcClient<HttpTransport>,
    account_type: AccountType,
    class_hash: Felt,
    signing_key: SigningKey,
    salt: Felt,
    chain_id: Felt,
    max_fee: Option<Felt>,
    wait_config: WaitForTx,
    version: DeployAccountVersion,
) -> Result<Felt, CreationError> {
    match account_type {
        AccountType::Oz => {
            deploy_oz_account(
                provider,
                class_hash,
                signing_key,
                salt,
                chain_id,
                max_fee,
                wait_config,
                version,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn deploy_oz_account(
    provider: &JsonRpcClient<HttpTransport>,
    class_hash: Felt,
    signing_key: SigningKey,
    salt: Felt,
    chain_id: Felt,
    max_fee: Option<Felt>,
    wait_config: WaitForTx,
    version: DeployAccountVersion,
) -> Result<Felt, CreationError> {
    let factory = OpenZeppelinAccountFactory::new(
        class_hash,
        chain_id,
        LocalWallet::from_signing_key(signing_key),
        provider,
    )
    .await
    .unwrap();

    deploy_account(
        factory,
        provider,
        salt,
        max_fee,
        wait_config,
        class_hash,
        version,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn simulate_deploy_oz_account(
    provider: &JsonRpcClient<HttpTransport>,
    class_hash: Felt,
    signing_key: SigningKey,
    salt: Felt,
    chain_id: Felt,
    max_fee: Option<Felt>,
    wait_config: WaitForTx,
    skip_validate: bool,
    skip_fee_charge: bool,
    version: DeployAccountVersion,
) -> Result<
    SimulateTransactionsResult<Felt>,
    crate::utils::v7::accounts::factory::AccountFactoryError<v7::signers::local_wallet::SignError>,
> {
    let factory = OpenZeppelinAccountFactory::new(
        class_hash,
        chain_id,
        LocalWallet::from_signing_key(signing_key),
        provider,
    )
    .await
    .unwrap();

    simulate_deployment(
        factory,
        provider,
        salt,
        max_fee,
        wait_config,
        class_hash,
        skip_validate,
        skip_fee_charge,
        version,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn estimate_fee_deploy_oz_account(
    provider: &JsonRpcClient<HttpTransport>,
    class_hash: Felt,
    signing_key: SigningKey,
    salt: Felt,
    chain_id: Felt,
    max_fee: Option<Felt>,
    wait_config: WaitForTx,
    skip_validate: bool,
    version: DeployAccountVersion,
) -> Result<
    FeeEstimate<Felt>,
    crate::utils::v7::accounts::factory::AccountFactoryError<v7::signers::local_wallet::SignError>,
> {
    let factory = OpenZeppelinAccountFactory::new(
        class_hash,
        chain_id,
        LocalWallet::from_signing_key(signing_key),
        provider,
    )
    .await
    .unwrap();

    estimate_fee_deployment(
        factory,
        provider,
        salt,
        max_fee,
        wait_config,
        class_hash,
        skip_validate,
        version,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn get_deployment_request(
    provider: &JsonRpcClient<HttpTransport>,
    account_type: AccountType,
    class_hash: Felt,
    signing_key: SigningKey,
    salt: Felt,
    chain_id: Felt,
    max_fee: Option<Felt>,
    wait_config: WaitForTx,
    version: DeployAccountVersion,
) -> Result<DeployAccountTxn<Felt>, CreationError> {
    let factory = OpenZeppelinAccountFactory::new(
        class_hash,
        chain_id,
        LocalWallet::from_signing_key(signing_key),
        provider,
    )
    .await
    .unwrap();
    match account_type {
        AccountType::Oz => {
            deploy_acc_request(
                factory,
                provider,
                salt,
                max_fee,
                wait_config,
                class_hash,
                version,
            )
            .await
        }
    }
}

#[allow(unused_variables)]
async fn deploy_account<T>(
    account_factory: T,
    provider: &JsonRpcClient<HttpTransport>,
    salt: Felt,
    max_fee: Option<Felt>,
    wait_config: WaitForTx,
    class_hash: Felt,
    version: DeployAccountVersion,
) -> Result<Felt, CreationError>
where
    T: AccountFactory + Sync,
{
    match version {
        DeployAccountVersion::V1 => {
            let deployment: crate::utils::v7::accounts::factory::AccountDeploymentV1<'_, T> =
                account_factory.deploy_v1(salt);
            let deploy_max_fee = if let Some(max_fee) = max_fee {
                max_fee
            } else {
                match deployment.estimate_fee().await {
                    Ok(max_fee) => Felt::from_dec_str(&max_fee.overall_fee.to_string())?,
                    Err(error) => return Err(CreationError::RpcError(error.to_string())),
                }
            };
            let result = deployment.send().await?;
            Ok(result.transaction_hash)
        }
        DeployAccountVersion::V3 => {
            let deployment: crate::utils::v7::accounts::factory::AccountDeploymentV3<'_, T> =
                account_factory.deploy_v3(salt);
            let deploy_max_fee = if let Some(max_fee) = max_fee {
                max_fee
            } else {
                match deployment.estimate_fee().await {
                    Ok(max_fee) => Felt::from_dec_str(&max_fee.overall_fee.to_string())?,
                    Err(error) => return Err(CreationError::RpcError(error.to_string())),
                }
            };
            let result = deployment.send().await?;
            Ok(result.transaction_hash)
        }
    }
}
#[allow(clippy::too_many_arguments)]
#[allow(unused_variables)]
async fn simulate_deployment<T>(
    account_factory: T,
    provider: &JsonRpcClient<HttpTransport>,
    salt: Felt,
    max_fee: Option<Felt>,
    wait_config: WaitForTx,
    class_hash: Felt,
    skip_validate: bool,
    skip_fee_charge: bool,
    version: DeployAccountVersion,
) -> Result<SimulateTransactionsResult<Felt>, AccountFactoryError<T::SignError>>
where
    T: AccountFactory + Sync,
{
    match version {
        DeployAccountVersion::V1 => {
            let deployment: crate::utils::v7::accounts::factory::AccountDeploymentV1<'_, T> =
                account_factory.deploy_v1(salt);
            deployment.simulate(skip_validate, skip_fee_charge).await
        }
        DeployAccountVersion::V3 => {
            let deployment: crate::utils::v7::accounts::factory::AccountDeploymentV3<'_, T> =
                account_factory.deploy_v3(salt);
            deployment.simulate(skip_validate, skip_fee_charge).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(unused_variables)]
async fn estimate_fee_deployment<T>(
    account_factory: T,
    provider: &JsonRpcClient<HttpTransport>,
    salt: Felt,
    max_fee: Option<Felt>,
    wait_config: WaitForTx,
    class_hash: Felt,
    skip_validate: bool,
    version: DeployAccountVersion,
) -> Result<FeeEstimate<Felt>, AccountFactoryError<T::SignError>>
where
    T: AccountFactory + Sync,
{
    match version {
        DeployAccountVersion::V1 => {
            let deployment: crate::utils::v7::accounts::factory::AccountDeploymentV1<'_, T> =
                account_factory.deploy_v1(salt);
            deployment.estimate_fee().await
        }
        DeployAccountVersion::V3 => {
            let deployment: crate::utils::v7::accounts::factory::AccountDeploymentV3<'_, T> =
                account_factory.deploy_v3(salt);
            match skip_validate {
                true => deployment.estimate_fee_skip_signature().await,
                false => deployment.estimate_fee().await,
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(unused_variables)]
async fn deploy_acc_request<T>(
    account_factory: T,
    provider: &JsonRpcClient<HttpTransport>,
    salt: Felt,
    max_fee: Option<Felt>,
    wait_config: WaitForTx,
    class_hash: Felt,
    version: DeployAccountVersion,
) -> Result<DeployAccountTxn<Felt>, CreationError>
where
    T: AccountFactory + Sync,
    v7::accounts::errors::CreationError:
        From<<T as v7::accounts::factory::AccountFactory>::SignError>,
{
    match version {
        DeployAccountVersion::V1 => {
            let deployment: crate::utils::v7::accounts::factory::AccountDeploymentV1<'_, T> =
                account_factory.deploy_v1(salt);
            Ok(DeployAccountTxn::V1(
                deployment
                    .prepare()
                    .await?
                    .get_deploy_request(false, false)
                    .await?,
            ))
        }
        DeployAccountVersion::V3 => {
            let deployment: crate::utils::v7::accounts::factory::AccountDeploymentV3<'_, T> =
                account_factory.deploy_v3(salt);
            Ok(DeployAccountTxn::V3(
                deployment
                    .prepare()
                    .await?
                    .get_deploy_request(false, false)
                    .await?,
            ))
        }
    }
}
