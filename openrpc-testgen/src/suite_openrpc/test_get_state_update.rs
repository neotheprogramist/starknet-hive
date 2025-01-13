use std::{path::PathBuf, str::FromStr};

use crate::{
    assert_result,
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
    RandomizableAccountsTrait, RunnableTrait,
};
use starknet_types_rpc::{BlockId, BlockTag};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl8_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl8_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        match test_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class.clone(), compiled_class_hash)
            .send()
            .await
        {
            Ok(class_and_txn_hash) => {
                wait_for_sent_transaction(
                    class_and_txn_hash.transaction_hash,
                    &test_input.random_paymaster_account.random_accounts()?,
                )
                .await?;

                let state_update = test_input
                    .random_paymaster_account
                    .provider()
                    .get_state_update(BlockId::Tag(BlockTag::Latest))
                    .await;

                let result = state_update.is_ok();

                assert_result!(result);

                let state_update = match state_update? {
                starknet_types_rpc::MaybePendingStateUpdate::Block(state_update) => state_update,
                starknet_types_rpc::MaybePendingStateUpdate::Pending(_) => {
                    return Err(OpenRpcTestGenError::ProviderError(
                        crate::utils::v7::providers::provider::ProviderError::UnexpectedPendingBlock,
                    ))
                }
            };

                let class_hash = state_update.state_diff.declared_classes[0]
                .class_hash
                .ok_or(OpenRpcTestGenError::ProviderError(
                crate::utils::v7::providers::provider::ProviderError::ClassHashNotFoundInStateUpdate,
            ))?;

                assert_result!(
                    class_hash == class_and_txn_hash.class_hash,
                    format!(
                        "Mismatch in transaction hash. Expected: {}, Found: {:?}.",
                        class_and_txn_hash.class_hash, class_hash
                    )
                );

                Ok(class_and_txn_hash.class_hash)
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
                    let full_error_message = format!("{:?}", e);

                    return Err(OpenRpcTestGenError::AccountError(AccountError::Other(
                        full_error_message,
                    )));
                }
            }
        }?;

        Ok(Self {})
    }
}
