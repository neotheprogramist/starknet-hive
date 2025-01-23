use crate::utils::v7::accounts::account::Account;
use crate::utils::v7::accounts::call::Call;
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::{assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::{
        accounts::account::ConnectedAccount,
        endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
        providers::provider::Provider,
    },
    RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{DaMode, InvokeTxn, Txn};
use t9n::txn_validation::invoke::verify_invoke_v3_signature;
#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let strk_address =
            Felt::from_hex("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D")?;
        let receiptent_address =
            Felt::from_hex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefd3ad")?;
        let transfer_amount = Felt::from_hex("0xfffffffffffffff")?;
        let sender = test_input.random_paymaster_account.random_accounts()?;
        let sender_nonce = sender.get_nonce().await?;
        let selector = get_selector_from_name("transfer")?;
        let calldata = vec![receiptent_address, transfer_amount, Felt::ZERO];
        let calls = vec![Call {
            to: strk_address,
            selector,
            calldata: calldata.clone(),
        }];
        let transfer_request = sender
            .execute_v3(calls.clone())
            .prepare()
            .await?
            .get_invoke_request(false, false)
            .await?;
        let signature = transfer_request.clone().signature;

        let (valid_signature, transfer_hash) = verify_invoke_v3_signature(
            &transfer_request,
            None,
            sender.provider().chain_id().await?.to_hex_string().as_str(),
        )?;

        let transfer_execution = sender.execute_v3(calls.clone()).send().await?;

        wait_for_sent_transaction(
            transfer_execution.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        assert_result!(
            transfer_execution.transaction_hash == transfer_hash,
            format!(
                "Exptected transaction hash to be {:?}, got {:?}",
                transfer_hash, transfer_execution.transaction_hash
            )
        );

        let txn = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_by_hash(transfer_execution.transaction_hash)
            .await;

        let result = txn.is_ok();
        assert_result!(result);

        let txn = match txn? {
            Txn::Invoke(InvokeTxn::V3(txn)) => txn,
            _ => return Err(OpenRpcTestGenError::Other("Expected InvokeTxn".to_string())),
        };

        assert_result!(
            txn.account_deployment_data.is_empty(),
            format!("Expected account deployment data to be empty, but got {txn:#?}")
        );

        let expected_calldata_len = 7;
        assert_result!(
            txn.calldata.len() == expected_calldata_len,
            format!("Expected calldata length to be {expected_calldata_len}, but got {txn:#?}")
        );

        let calldata_first = *txn.calldata.first().ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing first calldata element".to_string())
        })?;

        let calls_len_hex = Felt::from_dec_str(&calls.len().to_string())?;
        assert_result!(
            calldata_first == calls_len_hex,
            format!(
                "Expected first calldata element to be {:?}, but got {:?}",
                calls_len_hex, calldata_first
            )
        );

        let calldata_second = *txn.calldata.get(1).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing second calldata element".to_string())
        })?;

        assert_result!(
            calldata_second == strk_address,
            format!(
                "Expected second calldata element to be {:?}, but got {:?}",
                strk_address, calldata_second
            )
        );

        let calldata_third = *txn.calldata.get(2).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing third calldata element".to_string())
        })?;

        assert_result!(
            calldata_third == selector,
            format!(
                "Expected third calldata element to be {:?}, but got {:?}",
                selector, calldata_third
            )
        );

        let calldata_fourth = *txn.calldata.get(3).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing fourth calldata element".to_string())
        })?;
        let calldata_len_hex = Felt::from_dec_str(&calldata.len().to_string())?;
        assert_result!(
            calldata_fourth == calldata_len_hex,
            format!(
                "Expected fourth calldata element to be {:?}, but got {:?}",
                calldata_len_hex, calldata_fourth
            )
        );

        let calldata_fifth = *txn.calldata.get(4).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing fifth calldata element".to_string())
        })?;

        assert_result!(
            calldata_fifth == receiptent_address,
            format!(
                "Expected fifth calldata element to be {:?}, but got {:?}",
                receiptent_address, calldata_fifth
            )
        );

        let calldata_sixth = *txn.calldata.get(5).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing sixth calldata element".to_string())
        })?;

        assert_result!(
            calldata_sixth == transfer_amount,
            format!(
                "Expected sixth calldata element to be {:?}, but got {:?}",
                transfer_amount, calldata_sixth
            )
        );

        let calldata_seventh = *txn.calldata.get(6).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing seventh calldata element".to_string())
        })?;

        assert_result!(
            calldata_seventh == Felt::ZERO,
            format!(
                "Expected seventh calldata element to be {:?}, but got {:?}",
                Felt::ZERO,
                calldata_seventh
            )
        );

        let expected_fee_damode = DaMode::L1;
        assert_result!(
            txn.fee_data_availability_mode == expected_fee_damode,
            format!(
                "Expected fee data availability mode to be {:?}, but got {:?}",
                expected_fee_damode, txn.fee_data_availability_mode
            )
        );

        assert_result!(
            valid_signature,
            format!("Invalid signature, checked by t9n.",)
        );

        assert_result!(
            txn.signature == signature,
            format!(
                "Expected signature: {:?}, got {:?}",
                signature, txn.signature
            )
        );

        assert_result!(
            txn.nonce == sender_nonce,
            format!(
                "Expected nonce to be {:?}, but got {:?}",
                sender_nonce, txn.nonce
            )
        );

        let expected_nonce_damode = DaMode::L1;
        assert_result!(
            txn.nonce_data_availability_mode == expected_nonce_damode,
            format!(
                "Expected nonce data availability mode to be {:?}, but got {:?}",
                expected_nonce_damode, txn.nonce_data_availability_mode
            )
        );

        assert_result!(
            txn.paymaster_data.is_empty(),
            format!(
                "Expected paymaster data to be empty, but got {:?}",
                txn.paymaster_data
            )
        );

        let expected_l1gas_maxamount = String::from("0x261");
        assert_result!(
            txn.resource_bounds.l1_gas.max_amount == expected_l1gas_maxamount,
            format!(
                "Expected l1 gas max amount to be {:?}, but got {:?}",
                expected_l1gas_maxamount, txn.resource_bounds.l1_gas.max_amount
            )
        );

        let expected_l1gas_maxpriceperunit = String::from("0xf");
        assert_result!(
            txn.resource_bounds.l1_gas.max_price_per_unit == expected_l1gas_maxpriceperunit,
            format!(
                "Expected l1 gas max price per unit to be {:?}, but got {:?}",
                expected_l1gas_maxpriceperunit, txn.resource_bounds.l1_gas.max_price_per_unit
            )
        );

        let expected_l2gas_maxamount = String::from("0x0");
        assert_result!(
            txn.resource_bounds.l2_gas.max_amount == expected_l2gas_maxamount,
            format!(
                "Expected l2 gas max amount to be {:?}, but got {:?}",
                expected_l2gas_maxamount, txn.resource_bounds.l2_gas.max_amount
            )
        );

        let expected_l2gas_maxpriceperunit = String::from("0x0");
        assert_result!(
            txn.resource_bounds.l2_gas.max_price_per_unit == expected_l2gas_maxpriceperunit,
            format!(
                "Expected l2 gas max price per unit to be {:?}, but got {:?}",
                expected_l2gas_maxpriceperunit, txn.resource_bounds.l2_gas.max_price_per_unit
            )
        );

        let sender_address = sender.address();
        assert_result!(
            txn.sender_address == sender_address,
            format!(
                "Expected sender address to be {:?}, but got {:?}",
                sender_address, txn.sender_address
            )
        );

        Ok(Self {})
    }
}
