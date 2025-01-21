use std::path::PathBuf;
use std::str::FromStr;

use crate::utils::v7::accounts::account::{Account, ConnectedAccount};
use crate::utils::v7::endpoints::declare_contract::get_compiled_contract;
use crate::utils::v7::providers::provider::Provider;
use crate::{assert_eq_result, assert_matches_result, assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
    RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{
    BlockId, BlockTag, DeclareTransactionTrace, EntryPointType, FeeEstimate,
    SimulateTransactionsResult, TransactionTrace,
};
use t9n::txn_hashes::declare_hash::class_hash;

pub const STRK_ERC20_CONTRACT_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let account = test_input.random_paymaster_account.random_accounts()?;
        let acc_class_hash = test_input.account_class_hash;

        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
                PathBuf::from_str("target/dev/contracts_contracts_sample_contract_8_HelloStarknet.contract_class.json")?,
                PathBuf::from_str("target/dev/contracts_contracts_sample_contract_8_HelloStarknet.compiled_contract_class.json")?,
            )
            .await?;

        let estimate_fee = test_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class.clone(), compiled_class_hash)
            .estimate_fee()
            .await?;

        let nonce_before_simulate = account
            .provider()
            .get_nonce(BlockId::Tag(BlockTag::Pending), account.address())
            .await?;

        let simulate_declare_result = test_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class.clone(), compiled_class_hash)
            .simulate(false, true)
            .await;

        let nonce_after_simulate = account
            .provider()
            .get_nonce(BlockId::Tag(BlockTag::Pending), account.address())
            .await?;

        let class_hash = class_hash(flattened_sierra_class.clone());

        let result = simulate_declare_result.is_ok();

        assert_result!(result);

        let simulate_declare = simulate_declare_result?;

        assert_matches_result!(
            simulate_declare,
            SimulateTransactionsResult {
                fee_estimation: Some(FeeEstimate { .. }),
                transaction_trace: Some(TransactionTrace::Declare(DeclareTransactionTrace { .. }))
            }
        );

        let (fee_estimation, transaction_trace) = match simulate_declare {
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

        assert_matches_result!(
            transaction_trace,
            TransactionTrace::Declare(DeclareTransactionTrace { .. })
        );

        let declare_trace = match transaction_trace {
            TransactionTrace::Declare(declare_trace) => Ok(declare_trace),
            _ => Err(OpenRpcTestGenError::Other(
                "Expected DeclareTransactionTrace, but found a different transaction trace type"
                    .to_string(),
            )),
        }?;

        let validate_invocation = declare_trace.validate_invocation.ok_or_else(|| {
            OpenRpcTestGenError::Other(
                "Validate invocation is missing in deploy account trace".to_string(),
            )
        })?;

        let state_diff = declare_trace.state_diff.ok_or_else(|| {
            OpenRpcTestGenError::Other("State diff is missing in invoke trace".to_string())
        })?;

        let state_diff_nonce = state_diff
            .nonces
            .first()
            .and_then(|nonce| nonce.nonce)
            .ok_or_else(|| {
                OpenRpcTestGenError::Other("Nonce not found in state diff".to_string())
            })?;

        let validate_declare_selector = get_selector_from_name("__validate_declare__")?;

        // caller address
        let account_address = account.address();

        let entry_point_type_external = EntryPointType::External;

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

        // fee_transfer_invocation should be none because of skipFeeCharge flag
        assert_result!(
            declare_trace.fee_transfer_invocation.is_none(),
            "fee_transfer_invocation should be none."
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
            state_diff_class_hash == class_hash,
            format!(
                "Class hash mismatch: expected {:?}, but found {:?}",
                class_hash, state_diff_class_hash
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
