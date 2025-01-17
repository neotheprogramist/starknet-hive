use crate::{
    assert_result,
    utils::v7::{
        accounts::account::ConnectedAccount, endpoints::errors::OpenRpcTestGenError,
        providers::provider::Provider,
    },
    RunnableTrait,
};

/// These tests check node compatibility with spec version 0.7.1
const EXPECTED_SPEC_VERSION: &str = "0.7.1";

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let spec_version = test_input
            .random_paymaster_account
            .provider()
            .spec_version()
            .await;

        let result = spec_version.is_ok();

        assert_result!(result);

        let spec_version = spec_version?;

        assert_result!(
            spec_version == EXPECTED_SPEC_VERSION,
            format!(
                "Expected spec version to be {}, but got {}",
                EXPECTED_SPEC_VERSION, spec_version
            )
        );

        Ok(Self {})
    }
}
