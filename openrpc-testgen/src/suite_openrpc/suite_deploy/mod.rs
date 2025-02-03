use std::path::PathBuf;

use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, ClassAndTxnHash, DeclareTxn, EventFilterWithPageRequest, Txn};
use tracing::info;

use super::RandomSingleOwnerAccount;
use crate::{
    utils::v7::{
        accounts::account::{Account, AccountError, ConnectedAccount},
        endpoints::{
            declare_contract::{
                extract_class_hash_from_error, get_compiled_contract, parse_class_hash_from_error,
                RunnerError,
            },
            errors::OpenRpcTestGenError,
            utils::wait_for_sent_transaction,
        },
        providers::provider::{Provider, ProviderError},
    },
    RandomizableAccountsTrait, SetupableTrait,
};
use std::str::FromStr;
pub mod suite_contract_calls;
pub mod test_deploy_txn_v1;
pub mod test_deploy_txn_v1_invalid_class_hash;
pub mod test_deploy_txn_v3;
pub mod test_deploy_txn_v3_invalid_class_hash;
pub mod test_get_class_at;
pub mod test_get_class_hash_at;
pub mod test_get_txn_by_block_id_and_index_deploy_v1;
pub mod test_get_txn_by_block_id_and_index_deploy_v3;
pub mod test_get_txn_receipt_deploy;

#[derive(Clone, Debug)]
pub struct TestSuiteDeploy {
    pub random_paymaster_account: RandomSingleOwnerAccount,
    pub random_executable_account: RandomSingleOwnerAccount,
    pub declaration_result: ClassAndTxnHash<Felt>,
    pub account_class_hash: Felt,
}

impl SetupableTrait for TestSuiteDeploy {
    type Input = super::TestSuiteOpenRpc;

    async fn setup(setup_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) =
            get_compiled_contract(
                PathBuf::from_str("target/dev/contracts_contracts_sample_contract_3_HelloStarknet.contract_class.json")?,
            PathBuf::from_str("target/dev/contracts_contracts_sample_contract_3_HelloStarknet.compiled_contract_class.json")?,
            )
            .await?;

        let declaration_result = match setup_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class, compiled_class_hash)
            .send()
            .await
        {
            Ok(result) => {
                wait_for_sent_transaction(
                    result.transaction_hash,
                    &setup_input.random_paymaster_account.random_accounts()?,
                )
                .await?;
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

                    let provider = setup_input.random_paymaster_account.provider();
                    let random_account_address = setup_input
                        .random_paymaster_account
                        .random_accounts()?
                        .address();

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

        Ok(Self {
            random_paymaster_account: setup_input.random_paymaster_account.clone(),
            random_executable_account: setup_input.random_executable_account.clone(),
            declaration_result,
            account_class_hash: setup_input.account_class_hash,
        })
    }
}

#[cfg(not(feature = "rust-analyzer"))]
include!(concat!(
    env!("OUT_DIR"),
    "/generated_tests_suite_openrpc_suite_deploy.rs"
));
