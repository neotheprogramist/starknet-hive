use crate::utils::v7::accounts::account::{Account, ConnectedAccount};
use crate::utils::v7::accounts::creation::helpers::get_chain_id;
use crate::utils::v7::accounts::single_owner::{ExecutionEncoding, SingleOwnerAccount};
use crate::utils::v7::providers::provider::Provider;
use crate::utils::v7::signers::key_pair::SigningKey;
use crate::utils::v7::signers::local_wallet::LocalWallet;
use crate::{assert_eq_result, assert_matches_result, assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::{
        accounts::call::Call,
        endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
    },
    RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{
    BlockId, BlockTag, EntryPointType, ExecuteInvocation, FeeEstimate, FunctionCall,
    InvokeTransactionTrace, SimulateTransactionsResult, TransactionTrace,
};

pub const STRK_ERC20_CONTRACT_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteContractCalls;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let account = test_input.random_paymaster_account.random_accounts()?;

        let provider = account.provider().clone();

        let chain_id = get_chain_id(&provider).await?;

        let account_invalid = SingleOwnerAccount::new(
            account.provider().clone(),
            LocalWallet::from(SigningKey::from_random()),
            account.address(),
            chain_id,
            ExecutionEncoding::New,
        );
        let amount_to_increase = Felt::from_hex_unchecked("0x12345");
        let increase_balance_call = Call {
            to: test_input.deployed_contract_address,
            selector: get_selector_from_name("increase_balance")?,
            calldata: vec![amount_to_increase],
        };

        let estimate_fee = account
            .execute_v3(vec![increase_balance_call.clone()])
            .estimate_fee_skip_signature()
            .await?;

        let nonce_before_simulate = account
            .provider()
            .get_nonce(BlockId::Tag(BlockTag::Pending), account.address())
            .await?;

        let simulate_invoke_result = account_invalid
            .execute_v3(vec![increase_balance_call])
            .simulate(true, true)
            .await;

        let nonce_after_simulate = account
            .provider()
            .get_nonce(BlockId::Tag(BlockTag::Pending), account.address())
            .await?;

        let result = simulate_invoke_result.is_ok();

        assert_result!(result);

        let simulate_trace: SimulateTransactionsResult<Felt> = simulate_invoke_result?;

        assert_matches_result!(
            simulate_trace,
            SimulateTransactionsResult {
                fee_estimation: Some(FeeEstimate { .. }),
                transaction_trace: Some(TransactionTrace::Invoke(InvokeTransactionTrace { .. }))
            }
        );

        // Selectors
        let increase_balance_selector = get_selector_from_name("increase_balance")?;

        // Contract addresses
        let account_address = account.address();
        let deployed_contract_address = test_input.deployed_contract_address;

        let entry_point_type_external = EntryPointType::External;

        let (fee_estimation, transaction_trace) = match simulate_trace {
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

        let (function_invocation, invoke_trace) = match transaction_trace {
            TransactionTrace::Invoke(invoke_trace) => match invoke_trace.clone().execute_invocation
            {
                ExecuteInvocation::FunctionInvocation(func_invocation) => {
                    (Some(func_invocation), Some(invoke_trace))
                }
                _ => (None, Some(invoke_trace)),
            },
            _ => (None, None),
        };

        let invoke_trace = invoke_trace.ok_or_else(|| {
            OpenRpcTestGenError::Other("Invoke trace not found in transaction trace".to_string())
        })?;
        let execute_invocation = function_invocation.ok_or_else(|| {
            OpenRpcTestGenError::Other("Execute invocation not found in invoke trace".to_string())
        })?;

        let state_diff = invoke_trace.state_diff.ok_or_else(|| {
            OpenRpcTestGenError::Other("State diff is missing in invoke trace".to_string())
        })?;
        let state_diff_nonce = state_diff
            .nonces
            .first()
            .and_then(|nonce| nonce.nonce)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other("Nonce not found in state diff".to_string())
            })?;
        let storage_diff = state_diff.storage_diffs;

        let balance_call = account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![],
                    contract_address: test_input.deployed_contract_address,
                    entry_point_selector: get_selector_from_name("get_balance")?,
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await?;

        let balance = balance_call
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Balance not found".to_string()))?;

        // index of deployed_contract_address in storage_diffs
        let deployed_contract_index = storage_diff
            .iter()
            .position(|diff| diff.address == deployed_contract_address)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "Deployed contract address not found in storage diffs".to_string(),
                )
            })?;

        // Retrieve the first call from function_invocation
        let function_invocation_call = execute_invocation.calls.first().ok_or_else(|| {
            OpenRpcTestGenError::Other("No calls found in function invocation".to_string())
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

        // Validate nonces before and after simulate
        assert_result!(
        nonce_before_simulate == nonce_after_simulate,
        format!(
            "Nonce before and after simulate should be equal found: before simulate {:?}, after simulate {:?}",
            nonce_before_simulate ,
            nonce_after_simulate
        )
    );

        // Validate the contract address
        assert_result!(
        function_invocation_call.function_call.contract_address == deployed_contract_address,
        format!(
            "Contract address mismatch in nested call: expected call to {:?}, but found call to {:?}",
            deployed_contract_address, function_invocation_call.function_call.contract_address
        )
    );

        // Validate the caller address
        assert_result!(
            function_invocation_call.caller_address == account_address,
            format!(
                "Caller address mismatch in nested call: expected {:?}, but found {:?}",
                account_address, function_invocation_call.caller_address
            )
        );

        // Validate the entry point selector
        assert_result!(
            function_invocation_call.function_call.entry_point_selector
                == increase_balance_selector,
            format!(
                "Entry point selector mismatch in nested call: expected {:?}, but found {:?}",
                increase_balance_selector,
                function_invocation_call.function_call.entry_point_selector
            )
        );

        // Validate the entry point type
        assert_result!(
            function_invocation_call.entry_point_type == entry_point_type_external,
            format!(
                "Entry point type mismatch in nested call: expected {:?}, but found {:?}",
                entry_point_type_external, function_invocation_call.entry_point_type
            )
        );

        // fee_transfer_invocation should be None because of SkipFeeCharge == true
        assert_result!(
            invoke_trace.fee_transfer_invocation.is_none(),
            "fee_transfer_invocation should be None."
        );

        // state_diff nonces
        assert_result!(
            state_diff_nonce == nonce_before_simulate + Felt::ONE,
            format!(
                "Nonce mismatch: expected {:?}, but found {:?}",
                nonce_before_simulate + Felt::ONE,
                state_diff_nonce
            )
        );

        let state_diff_contract_address = state_diff
            .nonces
            .first()
            .and_then(|nonce| nonce.contract_address)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "Contract address not found in state diff nonces".to_string(),
                )
            })?;

        assert_result!(
            state_diff_contract_address == account_address,
            format!(
                "Contract address mismatch in state diff: expected {:?}, but found {:?}",
                account_address, state_diff_contract_address
            )
        );

        // Retrieve the storage diff for the deployed contract
        let deployed_contract_storage_diff =
            storage_diff.get(deployed_contract_index).ok_or_else(|| {
                OpenRpcTestGenError::Other(format!(
                    "No storage diff entry found for deployed contract at index {}",
                    deployed_contract_index
                ))
            })?;

        // Validate the deployed contract address in the storage diff
        assert_result!(
            deployed_contract_storage_diff.address == deployed_contract_address,
            format!(
                "Contract address mismatch in storage diff: expected {:?}, but found {:?}",
                deployed_contract_address, deployed_contract_storage_diff.address
            )
        );

        // state diff storage balance
        let storage_balance = deployed_contract_storage_diff
            .storage_entries
            .first()
            .and_then(|entry| entry.value)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "Value not found in deployed contract storage entries".to_string(),
                )
            })?;

        assert_result!(
            storage_balance == *balance + amount_to_increase,
            format!(
                "Balance mismatch in storage diff: expected {:?}, but found {:?}",
                balance + amount_to_increase,
                storage_balance
            )
        );

        // Validate that STRK_ERC20_CONTRACT_ADDRESS is not in storage_diffs
        assert!(
            !storage_diff
                .iter()
                .any(|diff| diff.address == STRK_ERC20_CONTRACT_ADDRESS),
            "STRK_ERC20_CONTRACT_ADDRESS should not be in storage diffs"
        );

        // validate_invocation should be None because of SkipValidate == true
        assert_result!(
            invoke_trace.validate_invocation.is_none(),
            "validate_invocation should be None."
        );

        Ok(Self {})
    }
}
