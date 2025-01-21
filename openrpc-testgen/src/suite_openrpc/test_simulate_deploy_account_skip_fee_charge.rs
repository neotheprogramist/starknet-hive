use crate::{
    assert_eq_result, assert_result,
    utils::v7::{
        accounts::{
            account::{Account, ConnectedAccount},
            call::Call,
            creation::create::{create_account, AccountType},
            deployment::{
                deploy::{
                    estimate_fee_deploy_account, simulate_deploy_account, DeployAccountVersion,
                },
                structs::{ValidatedWaitParams, WaitForTx},
            },
        },
        endpoints::{
            errors::OpenRpcTestGenError,
            utils::{get_selector_from_name, get_storage_var_address, wait_for_sent_transaction},
        },
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{EntryPointType, SimulateTransactionsResult, TransactionTrace};
pub const STRK_ERC20_CONTRACT_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let account_data = create_account(
            test_input.random_paymaster_account.provider(),
            AccountType::Oz,
            Option::None,
            Some(test_input.account_class_hash),
        )
        .await?;

        let transfer_amount = Felt::from_hex("0xfffffffffffffff")?;

        let transfer_execution = test_input
            .random_paymaster_account
            .execute_v3(vec![Call {
                to: Felt::from_hex(
                    "0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D",
                )?,
                selector: get_selector_from_name("transfer")?,
                calldata: vec![account_data.address, transfer_amount, Felt::ZERO],
            }])
            .send()
            .await?;

        wait_for_sent_transaction(
            transfer_execution.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let wait_config = WaitForTx {
            wait: true,
            wait_params: ValidatedWaitParams::default(),
        };

        let estimate_fee = estimate_fee_deploy_account(
            test_input.random_paymaster_account.provider(),
            test_input.random_paymaster_account.chain_id(),
            wait_config,
            account_data,
            false,
            DeployAccountVersion::V3,
        )
        .await?;

        let simulate_result = simulate_deploy_account(
            test_input.random_paymaster_account.provider(),
            test_input.random_paymaster_account.chain_id(),
            wait_config,
            account_data,
            false,
            true,
            DeployAccountVersion::V3,
        )
        .await;

        let result = simulate_result.is_ok();

        assert_result!(result);

        let simulate_result = simulate_result?;

        let (fee_estimation, transaction_trace) = match simulate_result {
            SimulateTransactionsResult {
                fee_estimation: Some(fee),
                transaction_trace: Some(trace),
            } => (Some(fee), Some(trace)),
            SimulateTransactionsResult {
                fee_estimation: Some(fee),
                transaction_trace: None,
            } => (Some(fee), None),
            SimulateTransactionsResult {
                fee_estimation: None,
                transaction_trace: Some(trace),
            } => (None, Some(trace)),
            _ => (None, None),
        };

        let fee_estimation = fee_estimation.ok_or_else(|| {
            OpenRpcTestGenError::Other(
                "Fee estimation is missing in simulate transaction".to_string(),
            )
        })?;

        let transaction_trace = transaction_trace.ok_or_else(|| {
            OpenRpcTestGenError::Other(
                "Transaction trace is missing in simulate transaction".to_string(),
            )
        })?;

        let deploy_acc_trace = match transaction_trace {
            TransactionTrace::DeployAccount(deploy_acc_trace) => Ok(deploy_acc_trace),
            _ => Err(OpenRpcTestGenError::Other(
                "Expected DeployAccountTransactionTrace, but found a different transaction trace type"
                    .to_string(),
            )),
        }?;

        let constructor_invocation = deploy_acc_trace.constructor_invocation;

        let state_diff = deploy_acc_trace.state_diff.ok_or_else(|| {
            OpenRpcTestGenError::Other("State diff is missing in deploy account trace".to_string())
        })?;
        let validate_invocation = deploy_acc_trace.validate_invocation.ok_or_else(|| {
            OpenRpcTestGenError::Other(
                "Validate invocation is missing in deploy account trace".to_string(),
            )
        })?;

        // Entry point types
        let entry_point_type_constructor = EntryPointType::Constructor;
        let entry_point_type_external = EntryPointType::External;

        // Selectors
        let constructor_selector = get_selector_from_name("constructor")?;
        let validate_deploy_selector = get_selector_from_name("__validate_deploy__")?;

        let public_key_storage_var = get_storage_var_address("Account_public_key", &[])?;

        // Retrieve the contract address from the state diff nonces
        let state_diff_nonce_contract_address = state_diff
            .nonces
            .first()
            .and_then(|nonce| nonce.contract_address)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "Contract address in nonces is missing in state diff".to_string(),
                )
            })?;

        // Retrieve the nonce from the state diff nonces
        let state_diff_nonce = state_diff
            .nonces
            .first()
            .and_then(|nonce| nonce.nonce)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other("Nonce is missing in state diff".to_string())
            })?;

        // index of deployed account address in storage_diffs
        let deployed_account_index = state_diff
            .storage_diffs
            .iter()
            .position(|diff| diff.address == account_data.address)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "Deployed contract address not found in storage diffs".to_string(),
                )
            })?;

        // Index of the public key storage variable in the storage entries
        let public_key_entry_index = state_diff
            .storage_diffs
            .get(deployed_account_index)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(format!(
                    "No storage diff found for deployed account index: {}",
                    deployed_account_index
                ))
            })?
            .storage_entries
            .iter()
            .position(|entry| entry.key == Some(public_key_storage_var))
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "Public key storage variable not found in storage entries".to_string(),
                )
            })?;

        // Retrieve the public key storage variable key from the storage entry
        let state_diff_public_key_storage_var = state_diff
            .storage_diffs
            .get(deployed_account_index)
            .and_then(|diff| diff.storage_entries.get(public_key_entry_index))
            .and_then(|entry| entry.key)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "Public key storage var is missing in storage entry".to_string(),
                )
            })?;

        // Retrieve the public key storage variable value from the storage entry
        let state_diff_public_key_storage_value = state_diff
            .storage_diffs
            .get(deployed_account_index)
            .and_then(|diff| diff.storage_entries.get(public_key_entry_index))
            .and_then(|entry| entry.value)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "Public key storage value is missing in storage entry".to_string(),
                )
            })?;

        // Retrieve the public key from constructor invocation calldata
        let public_key_in_calldata = constructor_invocation
            .function_call
            .calldata
            .first()
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "Public key is missing in constructor invocation calldata".to_string(),
                )
            })?;

        // Validate fee estimation
        assert_eq_result!(
            fee_estimation.data_gas_consumed,
            estimate_fee.data_gas_consumed,
            "data_gas_consumed mismatch: expected {:?}, but found {:?}",
            estimate_fee.data_gas_consumed,
            fee_estimation.data_gas_consumed
        );

        assert_eq_result!(
            fee_estimation.data_gas_price,
            estimate_fee.data_gas_price,
            "data_gas_price mismatch: expected {:?}, but found {:?}",
            estimate_fee.data_gas_price,
            fee_estimation.data_gas_price
        );

        assert_eq_result!(
            fee_estimation.gas_consumed,
            estimate_fee.gas_consumed,
            "gas_consumed mismatch: expected {:?}, but found {:?}",
            estimate_fee.gas_consumed,
            fee_estimation.gas_consumed
        );

        assert_eq_result!(
            fee_estimation.gas_price,
            estimate_fee.gas_price,
            "gas_price mismatch: expected {:?}, but found {:?}",
            estimate_fee.gas_price,
            fee_estimation.gas_price
        );

        assert_eq_result!(
            fee_estimation.overall_fee,
            estimate_fee.overall_fee,
            "overall_fee mismatch: expected {:?}, but found {:?}",
            estimate_fee.overall_fee,
            fee_estimation.overall_fee
        );

        assert_eq_result!(
            fee_estimation.unit,
            estimate_fee.unit,
            "unit mismatch: expected {:?}, but found {:?}",
            estimate_fee.unit,
            fee_estimation.unit
        );

        // Validate that the public key in constructor invocation calldata matches the account's verifying key
        assert_result!(
            *public_key_in_calldata == account_data.signing_key.verifying_key().scalar(),
            format!(
                "Public key mismatch in constructor invocation calldata: expected {:?}, but found {:?}",
                account_data.signing_key.verifying_key().scalar(), *public_key_in_calldata
            )
        );

        // Validate that the deployed account address in constructor invocation matches the account's address
        assert_result!(
            constructor_invocation.function_call.contract_address == account_data.address,
            format!(
                "Deployed account address mismatch in constructor invocation: expected {:?}, but found {:?}",
                account_data.address, constructor_invocation.function_call.contract_address
            )
        );

        // Validate that the constructor selector in constructor invocation matches the expected selector
        assert_result!(
            constructor_invocation.function_call.entry_point_selector == constructor_selector,
            format!(
                "Constructor selector mismatch in constructor invocation: expected {:?}, but found {:?}",
                constructor_selector, constructor_invocation.function_call.entry_point_selector
            )
        );

        // Validate that the class hash in constructor invocation matches the account's class hash
        assert_result!(
            constructor_invocation.class_hash == account_data.class_hash,
            format!(
                "Account class hash mismatch in constructor invocation: expected {:?}, but found {:?}",
                account_data.class_hash, constructor_invocation.class_hash
            )
        );

        // Validate that the entry point type in constructor invocation is of type 'CONSTRUCTOR'
        assert_result!(
            constructor_invocation.entry_point_type == entry_point_type_constructor,
            format!(
                "Entry point type mismatch in constructor invocation: expected {:?}, but found {:?}",
                entry_point_type_constructor, constructor_invocation.entry_point_type
            )
        );

        // Validate the fee_transfer_invocation is not in trace
        assert_result!(
            deploy_acc_trace.fee_transfer_invocation.is_none(),
            "Fee transfer invocation should be none."
        );

        let deployed_contract = state_diff.deployed_contracts.first().ok_or_else(|| {
            OpenRpcTestGenError::Other("No deployed contracts found in state diff".to_string())
        })?;

        // Validate that the deployed contract address in state diff matches the account's address
        assert_result!(
            deployed_contract.address == account_data.address,
            format!(
                "Deployed contract address mismatch in state diff: expected {:?}, but found {:?}",
                account_data.address, deployed_contract.address
            )
        );

        // Validate that the deployed contract class hash in state diff matches the account's class hash
        assert_result!(
            deployed_contract.class_hash == account_data.class_hash,
            format!(
                "Deployed contract class hash mismatch in state diff: expected {:?}, but found {:?}",
                account_data.class_hash, deployed_contract.class_hash
            )
        );

        // Validate that the contract address associated with the nonce in the state diff matches the account's address
        assert_result!(
            state_diff_nonce_contract_address == account_data.address,
            format!(
                "Contract address mismatch in state diff for nonce: expected {:?}, but found {:?}",
                account_data.address, state_diff_nonce_contract_address
            )
        );

        // Validate that the nonce in the state diff matches the expected nonce
        assert_result!(
            state_diff_nonce == Felt::ONE,
            format!(
                "Nonce mismatch in state diff: expected {:?}, but found {:?}",
                Felt::ONE,
                state_diff_nonce
            )
        );

        // Retrieve the deployed account address from state diff
        let deployed_account_address = state_diff
            .storage_diffs
            .get(deployed_account_index)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(format!(
                    "No storage diff found for deployed account index: {}",
                    deployed_account_index
                ))
            })?
            .address;

        // Validate that the deployed account address in the state diff matches the expected account address
        assert_result!(
            deployed_account_address == account_data.address,
            format!(
                "Deployed account address mismatch in state diff: expected {:?}, but found {:?}",
                account_data.address, deployed_account_address
            )
        );

        // Validate that the public key storage variable in the state diff matches the expected public key variable address
        assert_result!(
            state_diff_public_key_storage_var == public_key_storage_var,
            format!(
                "Public key storage variable mismatch in state diff: expected {:?}, but found {:?}",
                public_key_storage_var, state_diff_public_key_storage_var
            )
        );

        // Validate that the public key storage value in the state diff matches the account's public key
        assert_result!(
            state_diff_public_key_storage_value
                == account_data.signing_key.verifying_key().scalar(),
            format!(
                "Public key storage value mismatch in state diff: expected {:?}, but found {:?}",
                account_data.signing_key.verifying_key().scalar(),
                state_diff_public_key_storage_value
            )
        );

        // Validate the contract address in validate_invocation
        assert_result!(
            validate_invocation.function_call.contract_address == account_data.address,
            format!(
                "Account address mismatch in validate invocation: expected {:?}, but found {:?}",
                account_data.address, validate_invocation.function_call.contract_address
            )
        );

        // Validate the entry point selector in validate_invocation for validate_deploy
        assert_result!(
            validate_invocation.function_call.entry_point_selector == validate_deploy_selector,
            format!(
                "Entry point selector mismatch in validate invocation: expected {:?}, but found {:?}",
                validate_deploy_selector, validate_invocation.function_call.entry_point_selector
            )
        );

        // Validate the class hash in validate_invocation
        assert_result!(
            validate_invocation.class_hash == account_data.class_hash,
            format!(
                "Class hash mismatch in validate invocation: expected {:?}, but found {:?}",
                account_data.class_hash, validate_invocation.class_hash
            )
        );

        // Validate the entry point type in the validate_invocation is EXTERNAL
        assert_result!(
            validate_invocation.entry_point_type == entry_point_type_external,
            format!(
                "Entry point type mismatch in validate invocation: expected {:?}, but found {:?}",
                entry_point_type_external, validate_invocation.entry_point_type
            )
        );

        Ok(Self {})
    }
}
