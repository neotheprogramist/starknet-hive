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
        // Step 1: Get initial balance for a user
        let paymaster_address = test_input.random_paymaster_account.address();
        let initial_user_balance = *test_input
            .random_paymaster_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![paymaster_address],
                    contract_address: test_input.deployed_contract_address,
                    entry_point_selector: get_selector_from_name("get_user_balance")?,
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await?
            .first()
            .ok_or(OpenRpcTestGenError::Other(
                "Empty initial user balance".to_string(),
            ))?;

        let user_balance_slot = get_storage_var_address("balances", &[paymaster_address])?;
        let initial_storage_value = test_input
            .random_paymaster_account
            .provider()
            .get_storage_at(
                test_input.deployed_contract_address,
                user_balance_slot,
                BlockId::Tag(BlockTag::Latest),
            )
            .await?;

        // Step 2: Deposit funds into the user's balance
        let deposit_amount = Felt::from_hex("0x100")?;
        let deposit_call = Call {
            to: test_input.deployed_contract_address,
            selector: get_selector_from_name("deposit_l2")?,
            calldata: vec![paymaster_address, deposit_amount],
        };

        let invoke_result = test_input
            .random_paymaster_account
            .execute_v3(vec![deposit_call])
            .send()
            .await?;

        wait_for_sent_transaction(
            invoke_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        // Step 3: Verify updated balance
        let updated_user_balance = *test_input
            .random_paymaster_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![paymaster_address],
                    contract_address: test_input.deployed_contract_address,
                    entry_point_selector: get_selector_from_name("get_user_balance")?,
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await?
            .first()
            .ok_or(OpenRpcTestGenError::Other(
                "Empty updated user balance".to_string(),
            ))?;

        assert_result!(
            updated_user_balance == initial_user_balance + deposit_amount,
            format!(
                "Mismatch in user balance. Expected: {}, Found: {}.",
                initial_user_balance + deposit_amount,
                updated_user_balance
            )
        );

        // Step 4: Verify storage slot for user balance

        let updated_storage_value = test_input
            .random_paymaster_account
            .provider()
            .get_storage_at(
                test_input.deployed_contract_address,
                user_balance_slot,
                BlockId::Tag(BlockTag::Latest),
            )
            .await;

        let result = updated_storage_value.is_ok();
        assert_result!(result);

        let updated_storage_value = updated_storage_value?;

        assert_result!(
            updated_storage_value == initial_storage_value + deposit_amount,
            format!(
                "Storage value mismatch. Expected: {}, Found: {}.",
                initial_storage_value + deposit_amount,
                updated_storage_value
            )
        );

        assert_result!(
            updated_user_balance == initial_user_balance + deposit_amount,
            format!(
                "Mismatch in user balance. Expected: {}, Found: {}.",
                initial_user_balance + deposit_amount,
                updated_user_balance
            )
        );

        assert_result!(
            updated_storage_value == updated_user_balance,
            format!(
                "Storage value mismatch. Expected: {}, Found: {}.",
                updated_user_balance, updated_storage_value
            )
        );

        Ok(Self {})
    }
}
