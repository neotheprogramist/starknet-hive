use crate::{
    assert_matches_result,
    utils::v7::{
        accounts::account::AccountError,
        contract::factory::ContractFactory,
        endpoints::errors::OpenRpcTestGenError,
        providers::{jsonrpc::StarknetError, provider::ProviderError},
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use starknet_types_core::felt::Felt;

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteDeploy;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let factory = ContractFactory::new(
            Felt::from_hex_unchecked("0x1234"),
            test_input.random_paymaster_account.random_accounts()?,
        );
        let mut salt_buffer = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut salt_buffer[1..]);

        let invoke_result = factory
            .deploy_v1(vec![], Felt::from_bytes_be(&salt_buffer), true)
            .send()
            .await;

        assert_matches_result!(
            invoke_result.unwrap_err(),
            AccountError::Provider(ProviderError::StarknetError(
                StarknetError::TransactionExecutionError(_)
            ))
        );

        Ok(Self {})
    }
}
