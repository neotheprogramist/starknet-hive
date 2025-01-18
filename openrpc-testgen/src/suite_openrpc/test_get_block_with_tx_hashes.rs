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
                "target/dev/contracts_contracts_smpl6_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl6_HelloStarknet.compiled_contract_class.json",
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

        let block_with_tx_hashes: Result<
            starknet_types_rpc::MaybePendingBlockWithTxHashes<starknet_types_core::felt::Felt>,
            crate::utils::v7::providers::provider::ProviderError,
        > = test_input
            .random_paymaster_account
            .provider()
            .get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest))
            .await;

        let result = block_with_tx_hashes.is_ok();

        assert_result!(result);

        let block_with_tx_hashes = block_with_tx_hashes?;
        let tx_hash = match block_with_tx_hashes {
            starknet_types_rpc::MaybePendingBlockWithTxHashes::Block(block) => {
                *block.transactions.first().ok_or_else(|| {
                    OpenRpcTestGenError::Other(
                        "Expected block to have at least one transaction".to_string(),
                    )
                })?
            }
            starknet_types_rpc::MaybePendingBlockWithTxHashes::Pending(_) => {
                return Err(OpenRpcTestGenError::ProviderError(
                    crate::utils::v7::providers::provider::ProviderError::UnexpectedPendingBlock,
                ))
            }
        };

        assert_result!(
            tx_hash == declaration_result.transaction_hash,
            format!(
                "Mismatch in transaction hash. Expected: {}, Found: {}.",
                declaration_result.transaction_hash, tx_hash
            )
        );

        Ok(Self {})
    }
}
