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
                "target/dev/contracts_contracts_smpl8_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl8_HelloStarknet.compiled_contract_class.json",
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

        let state_update = test_input
            .random_paymaster_account
            .provider()
            .get_state_update(BlockId::Tag(BlockTag::Latest))
            .await;

        let result = state_update.is_ok();

        assert_result!(result);

        let state_update = match state_update? {
            starknet_types_rpc::MaybePendingStateUpdate::Block(state_update) => state_update,
            starknet_types_rpc::MaybePendingStateUpdate::Pending(_) => {
                return Err(OpenRpcTestGenError::ProviderError(
                    crate::utils::v7::providers::provider::ProviderError::UnexpectedPendingBlock,
                ))
            }
        };

        let class_hash = state_update
            .state_diff
            .declared_classes
            .first()
            .ok_or(OpenRpcTestGenError::Other(
                "No declared class in state update".to_string(),
            ))?
            .class_hash;

        assert_result!(
            class_hash == Some(declaration_result.class_hash),
            format!(
                "Mismatch in class hash. Expected: {:?}, Found: {:?}.",
                Some(declaration_result.class_hash),
                class_hash
            )
        );

        Ok(Self {})
    }
}
