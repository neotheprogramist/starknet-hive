use std::path::PathBuf;
use std::str::FromStr;

use crate::utils::v7::accounts::account::{Account, ConnectedAccount};
use crate::utils::v7::endpoints::declare_contract::get_compiled_contract;
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::provider::Provider;
use crate::{assert_matches_result, assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
    RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{
    BlockId, BlockTag, DeclareTransactionTrace, EntryPointType, TransactionTrace,
};

pub const STRK_ERC20_CONTRACT_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let account = test_input.random_paymaster_account.random_accounts()?;
        let acc_class_hash = test_input.account_class_hash;

        let nonce = account
            .provider()
            .get_nonce(BlockId::Tag(BlockTag::Pending), account.address())
            .await?;

        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
                PathBuf::from_str("target/dev/contracts_contracts_sample_contract_7_HelloStarknet.contract_class.json")?,
                PathBuf::from_str("target/dev/contracts_contracts_sample_contract_7_HelloStarknet.compiled_contract_class.json")?,
            )
            .await?;

        let declare_result = test_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class.clone(), compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declare_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let trace_result = account
            .provider()
            .trace_transaction(declare_result.transaction_hash)
            .await;

        let result = trace_result.is_ok();

        assert_result!(result);

        let trace = trace_result?;

        assert_matches_result!(
            trace,
            TransactionTrace::Declare(DeclareTransactionTrace { .. })
        );

        let declare_trace = match trace {
            TransactionTrace::Declare(declare_trace) => Ok(declare_trace),
            _ => Err(OpenRpcTestGenError::Other(
                "Expected DeclareTransactionTrace, but found a different transaction trace type"
                    .to_string(),
            )),
        }?;
        let fee_transfer_invocation = declare_trace.fee_transfer_invocation.ok_or_else(|| {
            OpenRpcTestGenError::Other(
                "Fee transfer invocation is missing in invoke trace".to_string(),
            )
        })?;

        let state_diff = declare_trace.state_diff.ok_or_else(|| {
            OpenRpcTestGenError::Other("State diff is missing in invoke trace".to_string())
        })?;

        let validate_invocation = declare_trace.validate_invocation.ok_or_else(|| {
            OpenRpcTestGenError::Other(
                "Validate invocation is missing in deploy account trace".to_string(),
            )
        })?;

        let state_diff_nonce = state_diff
            .nonces
            .first()
            .and_then(|nonce| nonce.nonce)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other("Nonce not found in state diff".to_string())
            })?;

        let transfer_selector = get_selector_from_name("transfer")?;
        let validate_declare_selector = get_selector_from_name("__validate_declare__")?;

        // caller address
        let account_address = account.address();

        let entry_point_type_external = EntryPointType::External;

        // fee_transfer_invocation STRK_ERC20_CONTRACT_ADDRESS
        assert_result!(
            fee_transfer_invocation.function_call.contract_address == STRK_ERC20_CONTRACT_ADDRESS,
            format!(
                "Contract address mismatch in fee transfer: expected {:?}, but found {:?}",
                STRK_ERC20_CONTRACT_ADDRESS, fee_transfer_invocation.function_call.contract_address
            )
        );

        // fee_transfer_invocation caller address
        assert_result!(
            fee_transfer_invocation.caller_address == account_address,
            format!(
                "Caller address mismatch in fee transfer: expected {:?}, but found {:?}",
                account_address, fee_transfer_invocation.caller_address
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

        // fee_transfer_invocation entry point type
        assert_result!(
            fee_transfer_invocation.entry_point_type == entry_point_type_external,
            format!(
                "Entry point type mismatch in nested call: expected {:?}, but found {:?}",
                entry_point_type_external, fee_transfer_invocation.entry_point_type
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

        // Validate that the contract address in the state diff matches the expected account address
        assert_result!(
            state_diff_contract_address == account_address,
            format!(
                "Contract address mismatch in state diff: expected {:?}, but found {:?}",
                account_address, state_diff_contract_address
            )
        );

        // Retrieve the class_hash from the state diff declared classes
        let state_diff_class_hash = state_diff
            .declared_classes
            .first()
            .and_then(|declared_class| declared_class.class_hash)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "class_hash not found in state diff declared classes".to_string(),
                )
            })?;

        // Validate that the class_hash in the state diff matches the class_hash from the declare result
        assert_result!(
            state_diff_class_hash == declare_result.class_hash,
            format!(
                "Class hash mismatch: expected {:?}, but found {:?}",
                declare_result.class_hash, state_diff_class_hash
            )
        );

        // Retrieve the compiled_class_hash from the state diff declared classes
        let state_diff_compiled_class_hash = state_diff
            .declared_classes
            .first()
            .and_then(|declared_class| declared_class.compiled_class_hash)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "compiled_class_hash not found in state diff declared classes".to_string(),
                )
            })?;

        // Validate that the compiled_class_hash matches the expected compiled_class_hash
        assert_result!(
            state_diff_compiled_class_hash == compiled_class_hash,
            format!(
                "Class hash mismatch: expected {:?}, but found {:?}",
                compiled_class_hash, state_diff_compiled_class_hash
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

        // Validate the entry point selector in validate_invocation for validate_deploy
        assert_result!(
            validate_invocation.function_call.entry_point_selector == validate_declare_selector,
            format!(
                "Entry point selector mismatch in validate invocation: expected {:?}, but found {:?}",
                validate_declare_selector, validate_invocation.function_call.entry_point_selector
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
