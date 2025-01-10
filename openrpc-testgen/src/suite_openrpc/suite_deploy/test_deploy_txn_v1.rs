use crate::{
    assert_result,
    utils::v7::{
        accounts::account::ConnectedAccount,
        contract::factory::ContractFactory,
        endpoints::{errors::OpenRpcTestGenError, utils::wait_for_sent_transaction},
        providers::provider::Provider,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteDeploy;

    /// Deploys a contract using `deploy_v1` endpoint and verifies that the declared class hash
    /// matches the deployed contract class hash in the state update.
    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let factory = ContractFactory::new(
            test_input.declaration_result.class_hash,
            test_input.random_paymaster_account.random_accounts()?,
        );
        let mut salt_buffer = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut salt_buffer[1..]);

        let invoke_result = factory
            .deploy_v1(vec![], Felt::from_bytes_be(&salt_buffer), true)
            .send()
            .await;

        wait_for_sent_transaction(
            invoke_result.as_ref().unwrap().transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let result = invoke_result.is_ok();

        assert_result!(result);

        let state_update: starknet_types_rpc::MaybePendingStateUpdate<Felt> = test_input
            .random_paymaster_account
            .provider()
            .get_state_update(BlockId::Tag(BlockTag::Latest))
            .await?;

        let state_update = match state_update {
            starknet_types_rpc::MaybePendingStateUpdate::Block(block) => Ok(block),
            starknet_types_rpc::MaybePendingStateUpdate::Pending(_) => {
                Err(OpenRpcTestGenError::ProviderError(
                    crate::utils::v7::providers::provider::ProviderError::UnexpectedPendingBlock,
                ))
            }
        }?;

        let state_update_deployed_contract_class_hash = state_update
            .state_diff
            .deployed_contracts
            .first()
            .ok_or(OpenRpcTestGenError::ProviderError(
                crate::utils::v7::providers::provider::ProviderError::MissingDeployedContract,
            ))?
            .class_hash;

        let class_hashes_equality =
            test_input.declaration_result.class_hash == state_update_deployed_contract_class_hash;

        assert_result!(
            class_hashes_equality,
            format!(
                "Mismatch in deployed contract class hash. Expected: {}, Actual: {}",
                test_input.declaration_result.class_hash, state_update_deployed_contract_class_hash
            )
        );

        Ok(Self {})
    }
}
