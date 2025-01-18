use std::{path::PathBuf, str::FromStr};

use crate::{
    assert_result,
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
use starknet_types_rpc::{BlockId, BlockTag};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl7_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl7_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let declaration_result = test_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class, compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declaration_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let block_txs = test_input
            .random_paymaster_account
            .provider()
            .get_block_with_txs(BlockId::Tag(BlockTag::Latest))
            .await;

        let result = block_txs.is_ok();

        assert_result!(result);

        let block_txs = block_txs?;
        let block_with_txs = match block_txs {
            starknet_types_rpc::MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
            starknet_types_rpc::MaybePendingBlockWithTxs::Pending(_) => {
                return Err(OpenRpcTestGenError::ProviderError(
                    crate::utils::v7::providers::provider::ProviderError::UnexpectedPendingBlock,
                ))
            }
        };

        let first_transaction = block_with_txs
            .transactions
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("no transactions in block".to_string()))?;

        assert_result!(
            first_transaction.transaction_hash == declaration_result.transaction_hash,
            format!(
                "Mismatch in transaction hash. Expected: {}, Found: {}.",
                declaration_result.transaction_hash, first_transaction.transaction_hash
            )
        );

        Ok(Self {})
    }
}
