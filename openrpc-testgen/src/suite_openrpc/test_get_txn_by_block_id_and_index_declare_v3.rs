use std::{path::PathBuf, str::FromStr};

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
use starknet_types_rpc::{BlockId, MaybePendingBlockWithTxs};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl3_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl3_HelloStarknet.compiled_contract_class.json",
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

                let block_hash = test_input
                    .random_paymaster_account
                    .provider()
                    .block_hash_and_number()
                    .await?
                    .block_hash;

                // Looking for txn index in the block
                let block_with_txns = test_input
                    .random_paymaster_account
                    .provider()
                    .get_block_with_txs(BlockId::Hash(block_hash))
                    .await?;
                let txn_index: u64 = match block_with_txns {
                    MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs
                        .transactions
                        .iter()
                        .position(|tx| tx.transaction_hash == class_and_txn_hash.transaction_hash)
                        .ok_or_else(|| {
                            OpenRpcTestGenError::TransactionNotFound(
                                class_and_txn_hash.transaction_hash.to_string(),
                            )
                        })?
                        .try_into()
                        .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
                    MaybePendingBlockWithTxs::Pending(block_with_txs) => block_with_txs
                        .transactions
                        .iter()
                        .position(|tx| tx.transaction_hash == class_and_txn_hash.transaction_hash)
                        .ok_or_else(|| {
                            OpenRpcTestGenError::TransactionNotFound(
                                class_and_txn_hash.transaction_hash.to_string(),
                            )
                        })?
                        .try_into()
                        .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
                };

                let txn = test_input
                    .random_paymaster_account
                    .provider()
                    .get_transaction_by_block_id_and_index(BlockId::Hash(block_hash), txn_index)
                    .await;

                let result = txn.is_ok();
                assert_result!(result);

                let declaration_transaction_by_hash = test_input
                    .random_paymaster_account
                    .provider()
                    .get_transaction_by_hash(class_and_txn_hash.transaction_hash)
                    .await?;

                assert_eq_result!(
                    txn?,
                    declaration_transaction_by_hash,
                    "Transaction by block id and index does not match the transaction by hash"
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
