use crate::{
    assert_matches_result, assert_result,
    utils::v7::{
        accounts::account::ConnectedAccount,
        endpoints::errors::OpenRpcTestGenError,
        providers::{
            jsonrpc::StarknetError,
            provider::{Provider, ProviderError},
        },
    },
    RunnableTrait,
};
use starknet_types_core::felt::Felt;

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let txn = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_by_hash(Felt::from_hex("0xdeadbeef")?)
            .await;

        let result = txn.is_err();
        assert_result!(result);

        assert_matches_result!(
            txn.unwrap_err(),
            ProviderError::StarknetError(StarknetError::TransactionHashNotFound)
        );

        Ok(Self {})
    }
}
