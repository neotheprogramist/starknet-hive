use serde_json::Value;
use starknet_types_rpc::{BlockId, BlockTag};

use crate::{
    assert_eq_result, assert_result,
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
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str("target/dev/contracts_contracts_sample_contract_2_HelloStarknet.contract_class.json")?,
            PathBuf::from_str("target/dev/contracts_contracts_sample_contract_2_HelloStarknet.compiled_contract_class.json")?,
        )
        .await?;

        let declaration_hash = match test_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class.clone(), compiled_class_hash)
            .send()
            .await
        {
            Ok(result) => {
                wait_for_sent_transaction(
                    result.transaction_hash,
                    &test_input.random_paymaster_account.random_accounts()?,
                )
                .await?;

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
                    let full_error_message = format!("{:?}", e);

                    return Err(OpenRpcTestGenError::AccountError(AccountError::Other(
                        full_error_message,
                    )));
                }
            }
        };

        let result = declaration_hash.is_ok();

        assert_result!(result);

        let declared_class = test_input
            .random_paymaster_account
            .provider()
            .get_class(BlockId::Tag(BlockTag::Latest), declaration_hash.unwrap())
            .await?;

        assert_eq_result!(
            declared_class
                .abi
                .as_ref()
                .and_then(|json| serde_json::from_str::<Value>(json).ok()),
            flattened_sierra_class
                .abi
                .as_ref()
                .and_then(|json| serde_json::from_str::<Value>(json).ok()),
            "ABI mismatch detected"
        );

        assert_eq_result!(
            declared_class.contract_class_version,
            flattened_sierra_class.contract_class_version,
            "Contract class version mismatch detected"
        );

        assert_eq_result!(
            declared_class.entry_points_by_type,
            flattened_sierra_class.entry_points_by_type,
            "Entry points mismatch detected"
        );

        assert_eq_result!(
            declared_class.sierra_program,
            flattened_sierra_class.sierra_program,
            "Sierra program mismatch detected"
        );

        Ok(Self {})
    }
}
