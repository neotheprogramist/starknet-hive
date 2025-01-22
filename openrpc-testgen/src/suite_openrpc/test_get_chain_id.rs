use starknet_types_core::felt::Felt;

use crate::{
    assert_result,
    utils::v7::{
        accounts::account::ConnectedAccount, endpoints::errors::OpenRpcTestGenError,
        providers::provider::Provider,
    },
    RunnableTrait,
};
const EXPECTED_CHAIN_ID: Felt = Felt::from_hex_unchecked("0x4d41444152415f4445564e4554");
#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let chain_id = test_input
            .random_paymaster_account
            .provider()
            .chain_id()
            .await;

        let result = chain_id.is_ok();

        assert_result!(result);

        let chain_id = chain_id?;

        assert_result!(
            chain_id == EXPECTED_CHAIN_ID,
            format!(
                "Mismatch chain id: {:?} != {:?}",
                chain_id, EXPECTED_CHAIN_ID
            )
        );

        Ok(Self {})
    }
}
