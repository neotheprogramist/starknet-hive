use core::fmt;
use std::{path::PathBuf, str::FromStr, time::Duration};

use rand::{rngs::StdRng, RngCore, SeedableRng};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{
    BlockId, BlockTag, ClassAndTxnHash, DeclareTxn, EventFilterWithPageRequest, Txn,
    TxnExecutionStatus, TxnFinalityAndExecutionStatus, TxnReceipt, TxnStatus,
};
use tracing::info;
use url::Url;

use crate::{
    utils::{
        random_single_owner_account::RandomSingleOwnerAccount,
        v7::{
            accounts::{
                account::{Account, AccountError, ConnectedAccount},
                call::Call,
                creation::{
                    create::{create_account, AccountType},
                    helpers::get_chain_id,
                },
                single_owner::{ExecutionEncoding, SingleOwnerAccount},
            },
            contract::factory::ContractFactory,
            endpoints::{
                declare_contract::{
                    extract_class_hash_from_error, get_compiled_contract,
                    parse_class_hash_from_error, RunnerError,
                },
                errors::{CallError, ContinuationTokenError, OpenRpcTestGenError},
                utils::get_selector_from_name,
            },
            providers::{
                jsonrpc::{HttpTransport, JsonRpcClient},
                provider::{Provider, ProviderError},
            },
            signers::{key_pair::SigningKey, local_wallet::LocalWallet},
        },
    },
    RandomizableAccountsTrait, SetupableTrait,
};

pub mod test_send_txs_with_invalid_signature;

#[derive(Clone, Debug)]
pub struct TestSuiteKatanaNoAccountValidation {
    pub random_paymaster_account: RandomSingleOwnerAccount,
    pub paymaster_private_key: Felt,
    pub random_executable_account: RandomSingleOwnerAccount,
    pub account_class_hash: Felt,
    pub udc_address: Felt,
    pub deployed_contract_address: Felt,
    pub dev_client: DevClient,
}

#[derive(Clone, Debug)]
pub struct SetupInput {
    pub urls: Vec<Url>,
    pub paymaster_account_address: Felt,
    pub paymaster_private_key: Felt,
    pub account_class_hash: Felt,
    pub udc_address: Felt,
}

impl SetupableTrait for TestSuiteKatanaNoAccountValidation {
    type Input = SetupInput;

    async fn setup(setup_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (executable_account_flattened_sierra_class, executable_account_compiled_class_hash) =
            get_compiled_contract(
                PathBuf::from_str("target/dev/contracts_ExecutableAccount.contract_class.json")?,
                PathBuf::from_str(
                    "target/dev/contracts_ExecutableAccount.compiled_contract_class.json",
                )?,
            )
            .await?;

        let dev_client = DevClient::new(setup_input.urls[0].clone());

        let provider = JsonRpcClient::new(HttpTransport::new(setup_input.urls[0].clone()));
        let chain_id = get_chain_id(&provider).await?;

        let paymaster_private_key =
            SigningKey::from_secret_scalar(setup_input.paymaster_private_key);

        let mut paymaster_account = SingleOwnerAccount::new(
            provider.clone(),
            LocalWallet::from(paymaster_private_key),
            setup_input.paymaster_account_address,
            chain_id,
            ExecutionEncoding::New,
        );

        paymaster_account.set_block_id(BlockId::Tag(BlockTag::Pending));

        let declare_executable_account_hash = match paymaster_account
            .declare_v3(
                executable_account_flattened_sierra_class.clone(),
                executable_account_compiled_class_hash,
            )
            .send()
            .await
        {
            Ok(result) => {
                wait_for_sent_transaction_katana(result.transaction_hash, &paymaster_account)
                    .await?;
                dev_client.generate_block().await?;
                Ok(result.class_hash)
            }
            Err(AccountError::Signing(sign_error)) => {
                if sign_error.to_string().contains("is already declared") {
                    Ok(parse_class_hash_from_error(&sign_error.to_string())?)
                } else {
                    Err(OpenRpcTestGenError::RunnerError(
                        RunnerError::AccountFailure(format!(
                            "Transaction execution error: {}",
                            sign_error
                        )),
                    ))
                }
            }

            Err(AccountError::Provider(ProviderError::Other(starkneterror))) => {
                if starkneterror.to_string().contains("is already declared") {
                    Ok(parse_class_hash_from_error(&starkneterror.to_string())?)
                } else {
                    Err(OpenRpcTestGenError::RunnerError(
                        RunnerError::AccountFailure(format!(
                            "Transaction execution error: {}",
                            starkneterror
                        )),
                    ))
                }
            }
            Err(e) => {
                let full_error_message = format!("{:?}", e);
                if full_error_message.contains("is already declared") {
                    Ok(extract_class_hash_from_error(&full_error_message)?)
                } else {
                    Err(OpenRpcTestGenError::AccountError(AccountError::Other(
                        full_error_message,
                    )))
                }
            }
        }?;

        let executable_account_data = create_account(
            &provider,
            AccountType::Oz,
            Option::None,
            Some(declare_executable_account_hash),
        )
        .await?;

        let deploy_executable_account_call: Call = Call {
            to: setup_input.udc_address,
            selector: get_selector_from_name("deployContract")?,
            calldata: vec![
                declare_executable_account_hash,
                executable_account_data.salt,
                Felt::ZERO,
                Felt::ONE,
                SigningKey::verifying_key(&executable_account_data.signing_key).scalar(),
            ],
        };

        let deploy_executable_account_result = paymaster_account
            .execute_v3(vec![deploy_executable_account_call])
            .send()
            .await?;

        wait_for_sent_transaction_katana(
            deploy_executable_account_result.transaction_hash,
            &paymaster_account,
        )
        .await?;

        dev_client.generate_block().await?;

        let mut executable_account = SingleOwnerAccount::new(
            provider.clone(),
            LocalWallet::from(executable_account_data.signing_key),
            executable_account_data.address,
            chain_id,
            ExecutionEncoding::New,
        );

        executable_account.set_block_id(BlockId::Tag(BlockTag::Pending));

        let mut paymaster_accounts = vec![];
        let mut executable_accounts = vec![];
        for url in &setup_input.urls {
            let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
            let chain_id = get_chain_id(&provider).await?;

            let paymaster_account = SingleOwnerAccount::new(
                provider.clone(),
                LocalWallet::from(paymaster_private_key),
                setup_input.paymaster_account_address,
                chain_id,
                ExecutionEncoding::New,
            );

            let executable_account = SingleOwnerAccount::new(
                provider.clone(),
                LocalWallet::from(executable_account_data.signing_key),
                executable_account_data.address,
                chain_id,
                ExecutionEncoding::New,
            );

            paymaster_accounts.push(paymaster_account);
            executable_accounts.push(executable_account);
        }

        let random_executable_account = RandomSingleOwnerAccount {
            accounts: executable_accounts,
        };
        let random_paymaster_account = RandomSingleOwnerAccount {
            accounts: paymaster_accounts,
        };

        let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(
            PathBuf::from_str("target/dev/contracts_contracts_sample_contract_1_HelloStarknet.contract_class.json")?,
        PathBuf::from_str("target/dev/contracts_contracts_sample_contract_1_HelloStarknet.compiled_contract_class.json")?,
        )
        .await?;

        let declaration_result = match random_paymaster_account
            .declare_v3(flattened_sierra_class, compiled_class_hash)
            .send()
            .await
        {
            Ok(result) => {
                wait_for_sent_transaction_katana(
                    result.transaction_hash,
                    &random_paymaster_account.random_accounts()?,
                )
                .await?;
                dev_client.generate_block().await?;
                Ok(result)
            }
            Err(AccountError::Signing(sign_error)) => {
                if sign_error.to_string().contains("is already declared") {
                    Ok(ClassAndTxnHash {
                        class_hash: parse_class_hash_from_error(&sign_error.to_string())?,
                        transaction_hash: Felt::ZERO,
                    })
                } else {
                    Err(OpenRpcTestGenError::RunnerError(
                        RunnerError::AccountFailure(format!(
                            "Transaction execution error: {}",
                            sign_error
                        )),
                    ))
                }
            }

            Err(AccountError::Provider(ProviderError::Other(starkneterror))) => {
                if starkneterror.to_string().contains("is already declared") {
                    Ok(ClassAndTxnHash {
                        class_hash: parse_class_hash_from_error(&starkneterror.to_string())?,
                        transaction_hash: Felt::ZERO,
                    })
                } else {
                    Err(OpenRpcTestGenError::RunnerError(
                        RunnerError::AccountFailure(format!(
                            "Transaction execution error: {}",
                            starkneterror
                        )),
                    ))
                }
            }
            Err(e) => {
                let full_error_message = format!("{:?}", e);

                if full_error_message.contains("is already declared") {
                    let class_hash = extract_class_hash_from_error(&full_error_message)?;

                    let filter = EventFilterWithPageRequest {
                        address: None,
                        from_block: Some(BlockId::Number(322421)),
                        to_block: Some(BlockId::Number(322421)),
                        keys: Some(vec![vec![]]),
                        chunk_size: 100,
                        continuation_token: None,
                    };

                    let provider = random_paymaster_account.provider();
                    let random_account_address =
                        random_paymaster_account.random_accounts()?.address();

                    let mut continuation_token = None;
                    let mut found_txn_hash = None;

                    loop {
                        let mut current_filter = filter.clone();
                        current_filter.continuation_token = continuation_token.clone();

                        let events_chunk = provider.get_events(current_filter).await?;

                        for event in events_chunk.events {
                            if event.event.data.contains(&random_account_address) {
                                let txn_hash = event.transaction_hash;

                                let txn_details =
                                    provider.get_transaction_by_hash(txn_hash).await?;

                                if let Txn::Declare(DeclareTxn::V3(declare_txn)) = txn_details {
                                    if declare_txn.class_hash == class_hash {
                                        found_txn_hash = Some(txn_hash);
                                        break;
                                    }
                                }
                            }
                        }

                        if found_txn_hash.is_some() {
                            break;
                        }

                        if let Some(token) = events_chunk.continuation_token {
                            continuation_token = Some(token);
                        } else {
                            break;
                        }
                    }

                    if let Some(tx_hash) = found_txn_hash {
                        Ok(ClassAndTxnHash {
                            class_hash,
                            transaction_hash: tx_hash,
                        })
                    } else {
                        info!("Transaction hash not found for the declared clas");
                        Err(OpenRpcTestGenError::RunnerError(
                            RunnerError::AccountFailure(
                                "Transaction hash not found for the declared class.".to_string(),
                            ),
                        ))
                    }
                } else {
                    return Err(OpenRpcTestGenError::AccountError(AccountError::Other(
                        full_error_message,
                    )));
                }
            }
        }?;

        let factory = ContractFactory::new(
            declaration_result.class_hash,
            random_paymaster_account.random_accounts()?,
        );
        let mut salt_buffer = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut salt_buffer[1..]);

        let deployment_result = factory
            .deploy_v3(vec![], Felt::from_bytes_be(&salt_buffer), true)
            .send()
            .await?;

        wait_for_sent_transaction_katana(
            deployment_result.transaction_hash,
            &random_paymaster_account.random_accounts()?,
        )
        .await?;
        dev_client.generate_block().await?;

        let deployment_receipt = random_paymaster_account
            .provider()
            .get_transaction_receipt(deployment_result.transaction_hash)
            .await?;

        let deployed_contract_address = match &deployment_receipt {
            TxnReceipt::Deploy(receipt) => receipt.contract_address,
            TxnReceipt::Invoke(receipt) => {
                if let Some(contract_address) = receipt
                    .common_receipt_properties
                    .events
                    .first()
                    .and_then(|event| event.data.first())
                {
                    *contract_address
                } else {
                    return Err(OpenRpcTestGenError::CallError(
                        CallError::UnexpectedReceiptType,
                    ));
                }
            }
            _ => {
                return Err(OpenRpcTestGenError::CallError(
                    CallError::UnexpectedReceiptType,
                ));
            }
        };

        dev_client.generate_block().await?;

        Ok(Self {
            random_executable_account,
            random_paymaster_account,
            paymaster_private_key: setup_input.paymaster_private_key,
            account_class_hash: setup_input.account_class_hash,
            udc_address: setup_input.udc_address,
            deployed_contract_address,
            dev_client,
        })
    }
}

#[derive(Clone, Debug)]
pub struct DevClient {
    pub url: Url,
}

impl DevClient {
    pub fn new(url: Url) -> Self {
        Self { url }
    }

    pub async fn generate_block(&self) -> Result<(), OpenRpcTestGenError> {
        let client = reqwest::Client::new();
        client
            .post(self.url.clone())
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "dev_generateBlock",
                "params": [],
                "id": 1
            }))
            .send()
            .await
            .map_err(OpenRpcTestGenError::RequestError)?;
        Ok(())
    }
}

pub async fn wait_for_sent_transaction_katana(
    transaction_hash: Felt,
    user_passed_account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
) -> Result<TxnFinalityAndExecutionStatus, OpenRpcTestGenError> {
    let start_fetching = std::time::Instant::now();
    let wait_for = Duration::from_secs(60);

    info!(
        "⏳ Waiting for transaction: {:?} to be mined.",
        transaction_hash
    );

    loop {
        if start_fetching.elapsed() > wait_for {
            return Err(OpenRpcTestGenError::Timeout(format!(
                "Transaction {:?} not mined in 60 seconds.",
                transaction_hash
            )));
        }

        // Check transaction status
        let status = match user_passed_account
            .provider()
            .get_transaction_status(transaction_hash)
            .await
        {
            Ok(status) => status,
            Err(_e) => {
                info!(
                    "Error while checking status for transaction: {:?}. Retrying...",
                    transaction_hash
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        match status {
            TxnFinalityAndExecutionStatus {
                finality_status: TxnStatus::AcceptedOnL2,
                execution_status: Some(TxnExecutionStatus::Succeeded),
                ..
            } => {
                info!(
                    "✅ Transaction {:?} Succeeded and accepted on L2. Finishing...",
                    transaction_hash
                );
                return Ok(status);
            }
            TxnFinalityAndExecutionStatus {
                finality_status: TxnStatus::AcceptedOnL2,
                execution_status: Some(TxnExecutionStatus::Reverted),
                ..
            } => {
                info!(
                    "❌ Transaction {:?} reverted on L2. Stopping...",
                    transaction_hash
                );
                return Err(OpenRpcTestGenError::TransactionFailed(
                    transaction_hash.to_string(),
                ));
            }
            TxnFinalityAndExecutionStatus {
                finality_status: TxnStatus::Rejected,
                ..
            } => {
                info!(
                    "❌ Transaction {:?} rejected. Stopping...",
                    transaction_hash
                );
                return Err(OpenRpcTestGenError::TransactionRejected(
                    transaction_hash.to_string(),
                ));
            }
            TxnFinalityAndExecutionStatus {
                finality_status: TxnStatus::Received,
                ..
            } => {
                info!(
                    "🛎️ Transaction {:?} received. Retrying...",
                    transaction_hash
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            TxnFinalityAndExecutionStatus {
                finality_status: TxnStatus::AcceptedOnL1,
                ..
            } => {
                info!("✅ Transaction acceoted on L1. Finishing...");
                return Ok(status);
            }

            _ => {
                info!(
                    "⏳ Transaction {} status not finalized. Retrying...",
                    transaction_hash
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        }
    }
}

/// Represents a continuation token for implementing paging in event queries.
///
/// This struct stores the necessary information to resume fetching events
/// from a specific point relative to the given filter passed as parameter to the
/// `starknet_getEvents` API, [EventFilter][starknet::core::types::EventFilter].
///
/// There JSON-RPC specification does not specify the format of the continuation token,
/// so how the node should handle it is implementation specific.
#[derive(PartialEq, Eq, Debug, Clone, Default)]
pub struct ContinuationToken {
    /// The block number to continue from.
    pub block_n: u64,
    /// The transaction number within the block to continue from.
    pub txn_n: u64,
    /// The event number within the transaction to continue from.
    pub event_n: u64,
}

impl ContinuationToken {
    pub fn parse(token: &str) -> Result<Self, ContinuationTokenError> {
        let arr: Vec<&str> = token.split(',').collect();
        if arr.len() != 3 {
            return Err(ContinuationTokenError::InvalidToken);
        }
        let block_n =
            u64::from_str_radix(arr[0], 16).map_err(ContinuationTokenError::ParseFailed)?;
        let receipt_n =
            u64::from_str_radix(arr[1], 16).map_err(ContinuationTokenError::ParseFailed)?;
        let event_n =
            u64::from_str_radix(arr[2], 16).map_err(ContinuationTokenError::ParseFailed)?;

        Ok(ContinuationToken {
            block_n,
            txn_n: receipt_n,
            event_n,
        })
    }
}

impl fmt::Display for ContinuationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x},{:x},{:x}", self.block_n, self.txn_n, self.event_n)
    }
}

#[cfg(not(feature = "rust-analyzer"))]
include!(concat!(
    env!("OUT_DIR"),
    "/generated_tests_suite_katana_no_account_validation.rs"
));
