use starknet_types_rpc::{BlockId, MaybePendingBlockWithTxs, SyncingStatus};

use crate::{
    assert_result,
    utils::v7::{
        accounts::account::ConnectedAccount,
        endpoints::errors::OpenRpcTestGenError,
        providers::provider::{Provider, ProviderError},
    },
    RunnableTrait,
};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let syncing_status = test_input
            .random_paymaster_account
            .provider()
            .syncing()
            .await;

        let result = syncing_status.is_ok();

        assert_result!(result);

        let syncing_status = syncing_status?;

        match syncing_status {
            SyncingStatus::NotSyncing => {}
            SyncingStatus::Syncing(status) => {
                let block_hash_and_number = test_input
                    .random_paymaster_account
                    .provider()
                    .block_hash_and_number()
                    .await?;

                assert_result!(
                    status.current_block_hash == block_hash_and_number.block_hash,
                    format!(
                        "Mismatch current block hash: {} != {}",
                        status.current_block_hash, block_hash_and_number.block_hash
                    )
                );
                assert_result!(
                    status.current_block_num == block_hash_and_number.block_number,
                    format!(
                        "Mismatch current block num: {} != {}",
                        status.current_block_num, block_hash_and_number.block_number
                    )
                );
                assert_result!(
                    status.highest_block_hash == block_hash_and_number.block_hash,
                    format!(
                        "Mismatch highest block hash: {} != {}",
                        status.highest_block_hash, block_hash_and_number.block_hash
                    )
                );
                assert_result!(
                    status.highest_block_num == block_hash_and_number.block_number,
                    format!(
                        "Mismatch highest block num: {} != {}",
                        status.highest_block_num, block_hash_and_number.block_number
                    )
                );

                let starting_block_num = 0;
                let maybe_pending_block_with_txs = test_input
                    .random_paymaster_account
                    .provider()
                    .get_block_with_txs(BlockId::Number(starting_block_num))
                    .await?;

                let starting_block_hash = match maybe_pending_block_with_txs {
                    MaybePendingBlockWithTxs::Block(block_with_txs) => {
                        block_with_txs.block_header.block_hash
                    }
                    _ => {
                        return Err(OpenRpcTestGenError::ProviderError(
                            ProviderError::UnexpectedPendingBlock,
                        ))
                    }
                };

                assert_result!(
                    status.starting_block_hash == starting_block_hash,
                    format!(
                        "Mismatch starting block hash: {} != {}",
                        status.highest_block_num, starting_block_hash
                    )
                );

                assert_result!(
                    status.starting_block_num == starting_block_num,
                    format!(
                        "Mismatch starting block num: {} != {}",
                        status.starting_block_num, starting_block_num
                    )
                );
            }
        }

        Ok(Self {})
    }
}
