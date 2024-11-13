use crate::{
    assert_result,
    utils::{
        conversions::felts_to_biguint::felts_slice_to_biguint,
        v7::{
            accounts::{
                account::{Account, AccountError, ConnectedAccount},
                call::Call,
            },
            contract::factory::ContractFactory,
            endpoints::{
                declare_contract::{
                    extract_class_hash_from_error, get_compiled_contract,
                    parse_class_hash_from_error, RunnerError,
                },
                endpoints_functions::OutsideExecution,
                errors::{CallError, RpcError},
                utils::{get_selector_from_name, wait_for_sent_transaction},
            },
            providers::provider::{Provider, ProviderError},
        },
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use cainome_cairo_serde::CairoSerde;
use colored::Colorize;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use starknet::core::crypto::ecdsa_sign;
use starknet_types_core::{
    felt::Felt,
    hash::{Poseidon, StarkHash},
};
use starknet_types_rpc::{BlockId, BlockTag, FunctionCall, TxnReceipt};
use std::path::PathBuf;
use std::str::FromStr;
use tracing::info;

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, RpcError> {
        let (erc_20_flattened_sierra_class, erc_20_compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str("target/dev/contracts_TestToken.contract_class.json")?,
            PathBuf::from_str("target/dev/contracts_TestToken.compiled_contract_class.json")?,
        )
        .await?;

        // Declare and deploy erc20
        let declaration_hash = match test_input
            .random_paymaster_account
            .declare_v3(erc_20_flattened_sierra_class, erc_20_compiled_class_hash)
            .send()
            .await
        {
            Ok(result) => Ok(result.class_hash),
            Err(AccountError::Signing(sign_error)) => {
                if sign_error.to_string().contains("is already declared") {
                    Ok(parse_class_hash_from_error(&sign_error.to_string())?)
                } else {
                    Err(RpcError::RunnerError(RunnerError::AccountFailure(format!(
                        "Transaction execution error: {}",
                        sign_error
                    ))))
                }
            }

            Err(AccountError::Provider(ProviderError::Other(starkneterror))) => {
                if starkneterror.to_string().contains("is already declared") {
                    Ok(parse_class_hash_from_error(&starkneterror.to_string())?)
                } else {
                    Err(RpcError::RunnerError(RunnerError::AccountFailure(format!(
                        "Transaction execution error: {}",
                        starkneterror
                    ))))
                }
            }
            Err(e) => {
                let full_error_message = format!("{:?}", e);
                Ok(extract_class_hash_from_error(&full_error_message)?)
            }
        };

        let factory = ContractFactory::new(
            declaration_hash?,
            test_input.random_paymaster_account.random_accounts()?,
        );
        let mut salt_buffer = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut salt_buffer[1..]);

        let deployment_result = factory
            .deploy_v3(vec![], Felt::from_bytes_be(&salt_buffer), true)
            .send()
            .await?;

        wait_for_sent_transaction(
            deployment_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let deployment_receipt_erc20 = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_receipt(deployment_result.transaction_hash)
            .await?;

        let contract_address_erc20 = match deployment_receipt_erc20 {
            TxnReceipt::Deploy(receipt) => receipt.contract_address,
            TxnReceipt::Invoke(receipt) => {
                if let Some(contract_address) = receipt
                    .common_receipt_properties
                    .events
                    .first()
                    .and_then(|event| event.data.first())
                {
                    *contract_address
                } else {
                    return Err(RpcError::CallError(CallError::UnexpectedReceiptType));
                }
            }
            _ => {
                return Err(RpcError::CallError(CallError::UnexpectedReceiptType));
            }
        };

        // Mint erc20 for the executable account
        let erc20_mint_call = Call {
            to: contract_address_erc20,
            selector: get_selector_from_name("mint")?,
            calldata: vec![
                test_input
                    .random_executable_account
                    .random_accounts()?
                    .address(),
                Felt::from_hex("0x123")?,
                Felt::ZERO,
            ],
        };

        test_input
            .random_paymaster_account
            .execute_v3(vec![erc20_mint_call])
            .send()
            .await?;

        // Prepare erc20 transfer call
        let account_erc20_receiver_address =
            Felt::from_hex("0x78662e7352d062084b0010068b99288486c2d8b914f6e2a55ce945f8792c8b1")?;
        let amount_to_transfer = vec![Felt::from_hex("0x100")?, Felt::ZERO];

        let erc20_transfer_call = Call {
            to: contract_address_erc20,
            selector: get_selector_from_name("transfer")?,
            calldata: vec![
                account_erc20_receiver_address,
                amount_to_transfer[0],
                amount_to_transfer[1],
            ],
        };

        let outside_execution = OutsideExecution {
            caller: test_input
                .random_paymaster_account
                .random_accounts()?
                .address(),
            nonce: Felt::ZERO,
            calls: vec![erc20_transfer_call],
        };

        let outside_execution_cairo_serialized =
            &OutsideExecution::cairo_serialize(&outside_execution);

        let hash = Poseidon::hash_array(outside_execution_cairo_serialized);

        let starknet::core::crypto::ExtendedSignature { r, s, v: _ } = ecdsa_sign(
            &Felt::from_hex("0x0000000000000000000000000000000071d7bb07b9a64f6f78ac4c816aff4da9")?, //paymaster pk
            &hash,
        )
        .unwrap();

        let mut calldata_to_executable_account_call = outside_execution_cairo_serialized.clone();
        calldata_to_executable_account_call.push(Felt::from_dec_str("2")?);
        calldata_to_executable_account_call.push(r);
        calldata_to_executable_account_call.push(s);

        let call_to_executable_account = Call {
            to: test_input
                .random_executable_account
                .random_accounts()?
                .address(),
            selector: get_selector_from_name("execute_from_outside")?,
            calldata: calldata_to_executable_account_call,
        };

        // Get the balances before transfer
        let exec_balance_before_transfer = test_input
            .random_executable_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![test_input
                        .random_executable_account
                        .random_accounts()?
                        .address()],
                    contract_address: contract_address_erc20,
                    entry_point_selector: get_selector_from_name("balance_of")?,
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await?;

        let paymaster_balance_before = test_input
            .random_paymaster_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![test_input
                        .random_paymaster_account
                        .random_accounts()?
                        .address()],
                    contract_address: Felt::from_hex(
                        "0x49D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7",
                    )?,
                    entry_point_selector: get_selector_from_name("balance_of")?,
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await?;

        test_input
            .random_paymaster_account
            .execute_v1(vec![call_to_executable_account])
            .send()
            .await?;

        let exec_balance_after_transfer = test_input
            .random_executable_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![test_input
                        .random_executable_account
                        .random_accounts()?
                        .address()],
                    contract_address: contract_address_erc20,
                    entry_point_selector: get_selector_from_name("balance_of")?,
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await?;

        let paymaster_balance_after = test_input
            .random_paymaster_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![test_input
                        .random_paymaster_account
                        .random_accounts()?
                        .address()],
                    contract_address: Felt::from_hex(
                        "0x49D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7",
                    )?,
                    entry_point_selector: get_selector_from_name("balance_of")?,
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await?;

        let receiver_balance_after_txn = test_input
            .random_paymaster_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![account_erc20_receiver_address],
                    contract_address: contract_address_erc20,
                    entry_point_selector: get_selector_from_name("balance_of")?,
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await?;

        // Prepare assert data
        let receiver_balance_after_txn = felts_slice_to_biguint(receiver_balance_after_txn)?;
        let amount_to_transfer = felts_slice_to_biguint(amount_to_transfer)?;

        assert_result!(
            receiver_balance_after_txn == amount_to_transfer,
            "Balances do not match"
        )?;

        let exec_balance_after_transfer = felts_slice_to_biguint(exec_balance_after_transfer)?;
        let exec_balance_before_transfer = felts_slice_to_biguint(exec_balance_before_transfer)?;

        assert_result!(
            exec_balance_before_transfer == exec_balance_after_transfer + amount_to_transfer,
            "Token balance on executable account did not decrease by the transfer amount."
        )?;

        let paymaster_balance_after = felts_slice_to_biguint(paymaster_balance_after)?;
        let paymaster_balance_before = felts_slice_to_biguint(paymaster_balance_before)?;
        assert_result!(
            paymaster_balance_after < paymaster_balance_before,
            "Gas balance on paymaster account did not decrease after transaction."
        )?;

        info!(
            "{} {}",
            "\n✓ Rpc test_erc20_transfer COMPATIBLE".green(),
            "✓".green()
        );

        Ok(Self {})
    }
}
