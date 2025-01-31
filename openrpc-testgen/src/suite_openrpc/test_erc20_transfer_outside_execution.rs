use crate::{
    assert_result,
    utils::{
        conversions::felts_to_biguint::felts_slice_to_biguint,
        get_balance::get_balance,
        outside_execution::{get_current_timestamp, prepare_outside_execution, OutsideExecution},
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
                errors::{CallError, OpenRpcTestGenError},
                utils::{get_selector_from_name, wait_for_sent_transaction},
            },
            providers::provider::{Provider, ProviderError},
        },
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use starknet_types_core::felt::Felt;

use starknet_types_rpc::{BlockId, BlockTag, TxnReceipt};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (erc_20_flattened_sierra_class, erc_20_compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str("target/dev/contracts_TestToken.contract_class.json")?,
            PathBuf::from_str("target/dev/contracts_TestToken.compiled_contract_class.json")?,
        )
        .await?;

        let declaration_hash = match test_input
            .random_paymaster_account
            .declare_v3(erc_20_flattened_sierra_class, erc_20_compiled_class_hash)
            .send()
            .await
        {
            Ok(result) => {
                wait_for_sent_transaction(
                    result.transaction_hash,
                    &test_input.random_paymaster_account.random_accounts()?,
                )
                .await?;

                Ok(result.class_hash)
            }
            Err(AccountError::Signing(sign_error)) => {
                if sign_error.to_string().contains("is already declared") {
                    Ok(parse_class_hash_from_error(&sign_error.to_string())?)
                } else {
                    Err(OpenRpcTestGenError::RunnerError(
                        RunnerError::AccountFailure(format!(
                            "Transaction execution error: {}",
                            sign_error
                        )),
                    ))
                }
            }

            Err(AccountError::Provider(ProviderError::Other(starkneterror))) => {
                if starkneterror.to_string().contains("is already declared") {
                    Ok(parse_class_hash_from_error(&starkneterror.to_string())?)
                } else {
                    Err(OpenRpcTestGenError::RunnerError(
                        RunnerError::AccountFailure(format!(
                            "Transaction execution error: {}",
                            starkneterror
                        )),
                    ))
                }
            }
            Err(e) => {
                let full_error_message = format!("{:?}", e);

                if full_error_message.contains("is already declared") {
                    Ok(extract_class_hash_from_error(&full_error_message)?)
                } else {
                    let full_error_message = format!("{:?}", e);

                    panic!("err {:?}", full_error_message);
                }
            }
        }?;

        let factory = ContractFactory::new(
            declaration_hash,
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
                    return Err(OpenRpcTestGenError::CallError(
                        CallError::UnexpectedReceiptType,
                    ));
                }
            }
            _ => {
                return Err(OpenRpcTestGenError::CallError(
                    CallError::UnexpectedReceiptType,
                ));
            }
        };

        let erc20_mint_call = Call {
            to: contract_address_erc20,
            selector: get_selector_from_name("mint")?,
            calldata: vec![
                test_input
                    .random_executable_account
                    .random_accounts()?
                    .address(),
                Felt::from_hex("0x1234")?,
                Felt::ZERO,
            ],
        };

        let res = test_input
            .random_paymaster_account
            .execute_v3(vec![erc20_mint_call])
            .send()
            .await?;

        wait_for_sent_transaction(
            res.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

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

        let timestamp =
            get_current_timestamp(test_input.random_paymaster_account.provider()).await?;

        let nonce = test_input
            .random_paymaster_account
            .provider()
            .get_nonce(
                BlockId::Tag(BlockTag::Latest),
                test_input.random_paymaster_account.address(),
            )
            .await?;

        let outside_execution = OutsideExecution {
            caller: test_input.random_paymaster_account.address(),
            execute_before: timestamp + 500,
            execute_after: timestamp - 500,
            nonce: nonce + Felt::ONE,
            calls: vec![erc20_transfer_call.clone()],
        };

        let calldata_to_executable_account_call = prepare_outside_execution(
            &outside_execution,
            test_input
                .random_executable_account
                .random_accounts()?
                .address(),
            test_input.executable_private_key,
            test_input
                .random_paymaster_account
                .provider()
                .chain_id()
                .await?,
        )
        .await?;

        let call_to_executable_account = Call {
            to: test_input
                .random_executable_account
                .random_accounts()?
                .address(),
            selector: get_selector_from_name("execute_from_outside_v2")?,
            calldata: calldata_to_executable_account_call,
        };

        let exec_balance_before_transfer = felts_slice_to_biguint(
            get_balance(
                &test_input.random_paymaster_account.provider(),
                test_input
                    .random_executable_account
                    .random_accounts()?
                    .address(),
                contract_address_erc20,
                BlockId::Tag(BlockTag::Pending),
            )
            .await?,
        )?;

        let paymaster_balance_before = felts_slice_to_biguint(
            get_balance(
                test_input.random_paymaster_account.provider(),
                test_input
                    .random_paymaster_account
                    .random_accounts()?
                    .address(),
                Felt::from_hex(
                    "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
                )?,
                BlockId::Tag(BlockTag::Pending),
            )
            .await?,
        )?;

        let receiver_balance_before_txn = felts_slice_to_biguint(
            get_balance(
                &test_input.random_paymaster_account.provider(),
                account_erc20_receiver_address,
                contract_address_erc20,
                BlockId::Tag(BlockTag::Pending),
            )
            .await?,
        )?;

        let hash = test_input
            .random_paymaster_account
            .execute_v3(vec![call_to_executable_account])
            .send()
            .await?;

        wait_for_sent_transaction(
            hash.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let exec_balance_after_transfer = felts_slice_to_biguint(
            get_balance(
                &test_input.random_paymaster_account.provider(),
                test_input
                    .random_executable_account
                    .random_accounts()?
                    .address(),
                contract_address_erc20,
                BlockId::Tag(BlockTag::Pending),
            )
            .await?,
        )?;

        let paymaster_balance_after = felts_slice_to_biguint(
            get_balance(
                test_input.random_paymaster_account.provider(),
                test_input
                    .random_paymaster_account
                    .random_accounts()?
                    .address(),
                Felt::from_hex(
                    "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
                )?,
                BlockId::Tag(BlockTag::Pending),
            )
            .await?,
        )?;

        let receiver_balance_after_txn = felts_slice_to_biguint(
            get_balance(
                &test_input.random_paymaster_account.provider(),
                account_erc20_receiver_address,
                contract_address_erc20,
                BlockId::Tag(BlockTag::Pending),
            )
            .await?,
        )?;

        let amount_to_transfer = felts_slice_to_biguint(amount_to_transfer)?;

        assert_result!(
            receiver_balance_after_txn == receiver_balance_before_txn + &amount_to_transfer,
            "Balances do not match"
        );

        assert_result!(
            exec_balance_before_transfer == exec_balance_after_transfer + amount_to_transfer,
            "Token balance on executable account did not decrease by the transfer amount."
        );

        assert_result!(
            paymaster_balance_after < paymaster_balance_before,
            "Fee token balance on paymaster account did not decrease after transaction."
        );

        Ok(Self {})
    }
}
