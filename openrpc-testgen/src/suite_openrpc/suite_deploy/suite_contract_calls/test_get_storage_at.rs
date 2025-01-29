use crate::{
    assert_result,
    utils::v7::{
        accounts::{
            account::{Account, ConnectedAccount},
            call::Call,
        },
        endpoints::{
            errors::OpenRpcTestGenError,
            utils::{get_selector_from_name, get_storage_var_address, wait_for_sent_transaction},
        },
        providers::provider::Provider,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag, FunctionCall};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteContractCalls;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        // Step 1: Call the deployed contract
        let initial_balance = *test_input
            .random_paymaster_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![],
                    contract_address: test_input.deployed_contract_address,
                    entry_point_selector: get_selector_from_name("get_balance")?,
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await?
            .first()
            .ok_or(OpenRpcTestGenError::Other(
                "Empty initial contract balance".to_string(),
            ))?;

        // Step 2: Get the storage value and get the storage value
        let contract_balance_slot = get_storage_var_address("balance", &[])?;

        let initial_storage_value = test_input
            .random_paymaster_account
            .provider()
            .get_storage_at(
                test_input.deployed_contract_address,
                contract_balance_slot,
                BlockId::Tag(BlockTag::Latest),
            )
            .await?;

        // Step 3: Update the storage value
        let balance_increase = Felt::from_hex("0x50")?;
        let increase_balance_call = Call {
            to: test_input.deployed_contract_address,
            selector: get_selector_from_name("increase_balance")?,
            calldata: vec![balance_increase],
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

        // Step 4: Get the updated balance via call and get the updated storage value
        let updated_balance = *test_input
            .random_paymaster_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![],
                    contract_address: test_input.deployed_contract_address,
                    entry_point_selector: get_selector_from_name("get_balance")?,
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await?
            .first()
            .ok_or(OpenRpcTestGenError::Other(
                "Empty updated contract balance".to_string(),
            ))?;

        let updated_storage_value = test_input
            .random_paymaster_account
            .provider()
            .get_storage_at(
                test_input.deployed_contract_address,
                contract_balance_slot,
                BlockId::Tag(BlockTag::Latest),
            )
            .await;

        // Step 5: Assert the updated balance and storage value
        let result = updated_storage_value.is_ok();
        assert_result!(result);

        let updated_storage_value = updated_storage_value?;

        assert_result!(
            updated_balance == initial_balance + balance_increase,
            format!(
                "Mismatch in updated balance. Expected: {}, Found: {}.",
                balance_increase, updated_balance
            )
        );

        assert_result!(
            updated_storage_value == initial_storage_value + balance_increase,
            format!(
                "Mismatch in updated storage value. Expected: {}, Found: {}.",
                balance_increase, updated_storage_value
            )
        );

        assert_result!(
            updated_storage_value == updated_balance,
            format!(
                "Updated storage value doesnt match updated balance. Updated storage value: {}, Updated balance: {}.",
                updated_storage_value, updated_balance
            )
        );

        println!(
            "deployed_contract_address {:#?}",
            test_input.deployed_contract_address,
        );

        println!("contract_balance_slot {:#?}", contract_balance_slot);

        Ok(Self {})
    }
}
