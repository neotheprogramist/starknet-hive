use crate::utils::v7::accounts::account::{Account, ConnectedAccount};
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::provider::Provider;
use crate::{assert_matches_result, assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::{
        accounts::call::Call,
        endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
    },
    RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{
    BlockId, BlockTag, EntryPointType, ExecuteInvocation, FunctionCall, InvokeTransactionTrace,
    TransactionTrace,
};

pub const STRK_ERC20_CONTRACT_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteContractCalls;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let amount_to_increase = Felt::from_hex_unchecked("0x321");
        let increase_balance_call = Call {
            to: test_input.deployed_contract_address,
            selector: get_selector_from_name("increase_balance")?,
            calldata: vec![amount_to_increase],
        };

        let account = test_input.random_paymaster_account.random_accounts()?;

        let nonce = account
            .provider()
            .get_nonce(BlockId::Tag(BlockTag::Pending), account.address())
            .await?;

        let invoke_result = account
            .execute_v3(vec![increase_balance_call])
            .send()
            .await?;

        wait_for_sent_transaction(invoke_result.transaction_hash, &account).await?;

        let trace_result = account
            .provider()
            .trace_transaction(invoke_result.transaction_hash)
            .await;

        let result = trace_result.is_ok();

        assert_result!(result);

        let trace = trace_result?;

        assert_matches_result!(
            trace,
            TransactionTrace::Invoke(InvokeTransactionTrace { .. })
        );

        // Selectors
        let increase_balance_selector = get_selector_from_name("increase_balance")?;
        let transfer_selector = get_selector_from_name("transfer")?;

        // Contract addresses
        let account_address = account.address();
        let deployed_contract_address = test_input.deployed_contract_address;

        let entry_point_type_external = EntryPointType::External;

        let (function_invocation, invoke_trace) = match trace {
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
        let function_invocation = function_invocation.ok_or_else(|| {
            OpenRpcTestGenError::Other("Function invocation not found in invoke trace".to_string())
        })?;
        let fee_transfer_invocation = invoke_trace.fee_transfer_invocation.ok_or_else(|| {
            OpenRpcTestGenError::Other(
                "Fee transfer invocation is missing in invoke trace".to_string(),
            )
        })?;

        let state_diff = invoke_trace.state_diff.ok_or_else(|| {
            OpenRpcTestGenError::Other("State diff is missing in invoke trace".to_string())
        })?;
        let state_diff_nonce = state_diff
            .nonces
            .get(0)
            .and_then(|nonce| nonce.nonce)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other("Nonce not found in state diff".to_string())
            })?;
        let storage_diff = state_diff.storage_diffs;

        let balance = account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![],
                    contract_address: test_input.deployed_contract_address,
                    entry_point_selector: get_selector_from_name("get_balance")?,
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await?[0];

        // index of deployed_contract_address in storage_diffs
        let deployed_contract_index = storage_diff
            .iter()
            .position(|diff| diff.address == deployed_contract_address)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "Deployed contract address not found in storage diffs".to_string(),
                )
            })?;

        // index of STRK_ERC20_CONTRACT_ADDRESS in storage_diffs
        let strk_erc20_index = storage_diff
            .iter()
            .position(|diff| diff.address == STRK_ERC20_CONTRACT_ADDRESS)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(format!(
                    "STRK_ERC20_CONTRACT_ADDRESS not found in storage diffs"
                ))
            })?;

        // function_invocation contract address
        assert_result!(
            function_invocation.calls[0].function_call.contract_address == deployed_contract_address,
            format!(
                "Contract address mismatch in nested call: expected call to {:?}, but found call to {:?}",
                deployed_contract_address, function_invocation.calls[0].function_call.contract_address
            )
        );

        // function_invocation caller address
        assert_result!(
            function_invocation.calls[0].caller_address == account_address,
            format!(
                "Caller address mismatch in nested call: expected {:?}, but found {:?}",
                account_address, function_invocation.calls[0].caller_address
            )
        );
        
        // function_invocation entry point selector
        assert_result!(
            function_invocation.calls[0]
                .function_call
                .entry_point_selector
                == increase_balance_selector,
            format!(
                "Entry point selector mismatch in nested call: expected {:?}, but found {:?}",
                increase_balance_selector,
                function_invocation.calls[0]
                    .function_call
                    .entry_point_selector
            )
        );

        // function_invocation entry point type
        assert_result!(
            function_invocation.calls[0].entry_point_type == entry_point_type_external,
            format!(
                "Entry point type mismatch in nested call: expected {:?}, but found {:?}",
                entry_point_type_external, function_invocation.calls[0].entry_point_type
            )
        );

        // fee_transfer_invocation STRK_ERC20_CONTRACT_ADDRESS
        assert_result!(
            fee_transfer_invocation.function_call.contract_address == STRK_ERC20_CONTRACT_ADDRESS,
            format!(
                "Contract address mismatch in fee transfer: expected {:?}, but found {:?}",
                STRK_ERC20_CONTRACT_ADDRESS, fee_transfer_invocation.function_call.contract_address
            )
        );

        // fee_transfer_invocation entry point selector
        assert_result!(
            fee_transfer_invocation.function_call.entry_point_selector == transfer_selector,
            format!(
                "Entry point selector mismatch in fee transfer: expected {:?}, but found {:?}",
                transfer_selector, fee_transfer_invocation.function_call.entry_point_selector
            )
        );

        // state_diff nonces
        assert_result!(
            state_diff_nonce == nonce + Felt::ONE,
            format!(
                "Nonce mismatch: expected {:?}, but found {:?}",
                nonce + Felt::ONE,
                state_diff_nonce
            )
        );

        let state_diff_contract_address = state_diff
            .nonces
            .get(0)
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

        // state diff storage diff deployed contract address
        assert_result!(
            storage_diff[deployed_contract_index].address == deployed_contract_address,
            format!(
                "Contract address mismatch in storage diff: expected {:?}, but found {:?}",
                deployed_contract_address, storage_diff[deployed_contract_index].address
            )
        );

        // state diff storage balance
        let storage_balance = storage_diff[deployed_contract_index]
            .storage_entries
            .get(0)
            .and_then(|entry| entry.value)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "Value not found in deployed contract storage entries".to_string(),
                )
            })?;

        assert_result!(
            storage_balance == balance,
            format!(
                "Balance mismatch in storage diff: expected {:?}, but found {:?}",
                balance, storage_balance
            )
        );

        // state diff storage STRK_ERC20_CONTRACT_ADDRESS
        assert_result!(
            storage_diff[strk_erc20_index].address == STRK_ERC20_CONTRACT_ADDRESS,
            format!(
                "STRK_ERC20_CONTRACT_ADDRESS address mismatch in storage diff: expected {:?}, but found {:?}",
                STRK_ERC20_CONTRACT_ADDRESS, storage_diff[strk_erc20_index].address
            )
        );

        Ok(Self {})
    }
}
