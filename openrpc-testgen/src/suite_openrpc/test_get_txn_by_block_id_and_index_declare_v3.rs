use std::{path::PathBuf, str::FromStr};

use crate::{
    assert_eq_result, assert_result,
    utils::v7::{
        accounts::account::{Account, ConnectedAccount},
        endpoints::{
            declare_contract::get_compiled_contract, errors::OpenRpcTestGenError,
            utils::wait_for_sent_transaction,
        },
        providers::provider::Provider,
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
                "target/dev/contracts_contracts_smpl16_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl16_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let declaration_hash = test_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class, compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declaration_hash.transaction_hash,
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
                .position(|tx| tx.transaction_hash == declaration_hash.transaction_hash)
                .ok_or_else(|| {
                    OpenRpcTestGenError::TransactionNotFound(
                        declaration_hash.transaction_hash.to_string(),
                    )
                })?
                .try_into()
                .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
            MaybePendingBlockWithTxs::Pending(block_with_txs) => block_with_txs
                .transactions
                .iter()
                .position(|tx| tx.transaction_hash == declaration_hash.transaction_hash)
                .ok_or_else(|| {
                    OpenRpcTestGenError::TransactionNotFound(
                        declaration_hash.transaction_hash.to_string(),
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
            .get_transaction_by_hash(declaration_hash.transaction_hash)
            .await?;

        assert_eq_result!(
            txn?,
            declaration_transaction_by_hash,
            "Transaction by block id and index does not match the transaction by hash"
        );

        Ok(Self {})
    }
}
