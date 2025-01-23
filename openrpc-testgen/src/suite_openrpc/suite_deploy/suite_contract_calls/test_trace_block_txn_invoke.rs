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
    TraceBlockTransactionsResult, TransactionTrace,
};

use t9n::txn_validation::invoke::verify_invoke_v3_signature;

pub const STRK_ERC20_CONTRACT_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteContractCalls;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let account = test_input.random_paymaster_account.random_accounts()?;

        let amount_to_increase = Felt::from_hex_unchecked("0x123");
        let increase_balance_call = Call {
            to: test_input.deployed_contract_address,
            selector: get_selector_from_name("increase_balance")?,
            calldata: vec![amount_to_increase],
        };

        let chain_id = account.provider().chain_id().await?;

        let nonce = account
            .provider()
            .get_nonce(BlockId::Tag(BlockTag::Pending), account.address())
            .await?;

        let prepared_execution_v3 = test_input
            .random_paymaster_account
            .execute_v3(vec![increase_balance_call])
            .prepare()
            .await?;

        let invoke_request = prepared_execution_v3
            .get_invoke_request(false, false)
            .await?;

        let (_, invoke_hash) =
            verify_invoke_v3_signature(&invoke_request, None, chain_id.to_hex_string().as_str())?;

        let invoke_result = prepared_execution_v3
            .send_from_request(invoke_request)
            .await?;

        wait_for_sent_transaction(invoke_result.transaction_hash, &account).await?;

        assert_result!(
            invoke_result.transaction_hash == invoke_hash,
            format!(
                "Mismatch transaction hash: expected from t9n {:?} got {:?}",
                invoke_hash, invoke_result.transaction_hash
            )
        );

        let trace_block_result = test_input
            .random_paymaster_account
            .provider()
            .trace_block_transactions(BlockId::Tag(BlockTag::Latest))
            .await;

        let result = trace_block_result.is_ok();

        assert_result!(result);

        let trace = trace_block_result?;

        let trace_len = trace.len();

        assert_result!(
            trace_len == 1,
            format!(
                "Trace block length missmatch expected: 1, got: {}",
                trace_len
            )
        );

        let trace_block = trace
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Trace block not found".to_string()))?;

        assert_matches_result!(
            trace_block,
            TraceBlockTransactionsResult {
                trace_root: Some(TransactionTrace::Invoke(InvokeTransactionTrace { .. })),
                transaction_hash: Some(_),
            }
        );

        let trace_root = trace_block.trace_root.clone().ok_or_else(|| {
            OpenRpcTestGenError::Other("Trace root not found in trace block".to_string())
        })?;
        let transaction_hash = trace_block.transaction_hash.ok_or_else(|| {
            OpenRpcTestGenError::Other("Transaction hash not found in trace block".to_string())
        })?;

        let (function_invocation, invoke_trace) = match trace_root {
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

        let validate_invocation = invoke_trace.validate_invocation.ok_or_else(|| {
            OpenRpcTestGenError::Other("Validate invocation is missing in invoke trace".to_string())
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

        // Selectors
        let increase_balance_selector = get_selector_from_name("increase_balance")?;
        let transfer_selector = get_selector_from_name("transfer")?;
        let validate_selector = get_selector_from_name("__validate__")?;

        // Contract addresses
        let account_address = account.address();
        let deployed_contract_address = test_input.deployed_contract_address;
        let acc_class_hash = test_input.account_class_hash;

        let entry_point_type_external = EntryPointType::External;

        assert_result!(
            transaction_hash == invoke_hash,
            format!(
                "Transaction hash mismatch: expected {:?}, but found {:?}",
                invoke_hash, transaction_hash
            )
        );

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
                OpenRpcTestGenError::Other(
                    "STRK_ERC20_CONTRACT_ADDRESS not found in storage diffs".to_string(),
                )
            })?;

        // Retrieve the first call from function_invocation
        let function_invocation_call = function_invocation.calls.first().ok_or_else(|| {
            OpenRpcTestGenError::Other("No calls found in function invocation".to_string())
        })?;

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
            storage_balance == balance,
            format!(
                "Balance mismatch in storage diff: expected {:?}, but found {:?}",
                balance, storage_balance
            )
        );

        // Retrieve the storage diff for STRK_ERC20_CONTRACT_ADDRESS
        let strk_erc20_storage_diff = storage_diff.get(strk_erc20_index).ok_or_else(|| {
            OpenRpcTestGenError::Other(format!(
                "No storage diff entry found for STRK_ERC20_CONTRACT_ADDRESS at index {}",
                strk_erc20_index
            ))
        })?;

        // Validate the STRK_ERC20_CONTRACT_ADDRESS in the storage diff
        assert_result!(
            strk_erc20_storage_diff.address == STRK_ERC20_CONTRACT_ADDRESS,
            format!(
                "STRK_ERC20_CONTRACT_ADDRESS mismatch in storage diff: expected {:?}, but found {:?}",
                STRK_ERC20_CONTRACT_ADDRESS, strk_erc20_storage_diff.address
            )
        );

        // Validate the contract address in validate_invocation
        assert_result!(
            validate_invocation.function_call.contract_address == account_address,
            format!(
                "Account address mismatch in validate invocation: expected {:?}, but found {:?}",
                account_address, validate_invocation.function_call.contract_address
            )
        );

        // Validate the entry point selector in validate_invocation
        assert_result!(
            validate_invocation.function_call.entry_point_selector == validate_selector,
            format!(
                "Entry point selector mismatch in validate invocation: expected {:?}, but found {:?}",
                validate_selector, validate_invocation.function_call.entry_point_selector
            )
        );

        // Validate the class hash in validate_invocation
        assert_result!(
            validate_invocation.class_hash == acc_class_hash,
            format!(
                "Class hash mismatch in validate invocation: expected {:?}, but found {:?}",
                acc_class_hash, validate_invocation.class_hash
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
