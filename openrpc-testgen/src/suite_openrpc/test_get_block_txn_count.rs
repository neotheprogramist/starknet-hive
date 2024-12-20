use crate::{
    assert_result,
    utils::v7::{
        accounts::account::ConnectedAccount, endpoints::errors::OpenRpcTestGenError,
        providers::provider::Provider,
    },
    RunnableTrait,
};
use starknet_types_rpc::{BlockId, BlockTag};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let block_txn_count = test_input
            .random_paymaster_account
            .provider()
            .get_block_transaction_count(BlockId::Tag(BlockTag::Latest))
            .await;

        let result = block_txn_count.is_ok();

        assert_result!(result);

        Ok(Self {})
    }
}
