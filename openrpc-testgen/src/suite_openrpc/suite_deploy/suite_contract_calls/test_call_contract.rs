use crate::utils::v7::accounts::account::{Account, ConnectedAccount};
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::provider::Provider;
use crate::{assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::{
        accounts::call::Call,
        endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
    },
    RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag, FunctionCall};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteContractCalls;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let initial_balance = *test_input
            .random_paymaster_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![],
                    contract_address: test_input.deployed_contract_address,
                    entry_point_selector: get_selector_from_name("get_balance")?,
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await?
            .first()
            .ok_or(OpenRpcTestGenError::Other(
                "Empty initial contract balance".to_string(),
            ))?;

        let amount_to_increase = Felt::from_hex_unchecked("0x50");
        let increase_balance_call = Call {
            to: test_input.deployed_contract_address,
            selector: get_selector_from_name("increase_balance")?,
            calldata: vec![amount_to_increase],
        };

        let invoke_result = test_input
            .random_paymaster_account
            .execute_v3(vec![increase_balance_call])
            .send()
            .await?;

        wait_for_sent_transaction(
            invoke_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let updated_balance = test_input
            .random_paymaster_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![],
                    contract_address: test_input.deployed_contract_address,
                    entry_point_selector: get_selector_from_name("get_balance")?,
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await;

        let result = updated_balance.is_ok();

        assert_result!(result);

        let updated_balance = *updated_balance?.first().ok_or(OpenRpcTestGenError::Other(
            "Empty updated contract balance".to_string(),
        ))?;

        assert_result!(
            updated_balance == initial_balance + amount_to_increase,
            format!(
                "Unexpected balance. Expected: {:?}, Found: {:?}",
                initial_balance + amount_to_increase,
                updated_balance
            )
        );

        Ok(Self {})
    }
}
