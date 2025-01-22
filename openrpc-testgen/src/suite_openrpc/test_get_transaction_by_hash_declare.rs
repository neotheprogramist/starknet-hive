use std::fmt::format;
use std::path::PathBuf;
use std::str::FromStr;

use crate::utils::v7::accounts::account::Account;
use crate::utils::v7::accounts::call::Call;
use crate::utils::v7::endpoints::declare_contract::get_compiled_contract;
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
use starknet_types_rpc::{DaMode, DeclareTxn, InvokeTxn, Txn};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl16_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl16_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let sender = test_input.random_paymaster_account.random_accounts()?;
        let initial_sender_nonce = sender.get_nonce().await?;
        let declaration_result = sender
            .declare_v3(flattened_sierra_class, compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declaration_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let txn = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_by_hash(declaration_result.transaction_hash)
            .await;

        let result = txn.is_ok();
        assert_result!(result);

        let txn = match txn? {
            Txn::Declare(DeclareTxn::V3(txn)) => txn,
            _ => return Err(OpenRpcTestGenError::Other("Expected InvokeTxn".to_string())),
        };

        assert_result!(
            txn.account_deployment_data.is_empty(),
            format!(
                "Expected no account deployment data, but got {:?}",
                txn.account_deployment_data
            )
        );

        assert_result!(
            txn.class_hash == declaration_result.class_hash,
            format!(
                "Expected class hash to be {:?}, but got {:?}",
                declaration_result.class_hash, txn.class_hash
            )
        );

        assert_result!(
            txn.compiled_class_hash == compiled_class_hash,
            format!(
                "Expected compiled class hash to be {:?}, but got {:?}",
                compiled_class_hash, txn.compiled_class_hash
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
            txn.nonce == initial_sender_nonce,
            format!(
                "
            Expected nonce to be {:?}, but got {:?}",
                initial_sender_nonce, txn.nonce
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
                "Expected no paymaster data, but got {:?}",
                txn.paymaster_data
            )
        );

        let expected_l1gas_maxamount = String::from("0xb800");

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

        let expected_tip = String::from("0x0");
        assert_result!(
            txn.tip == expected_tip,
            format!(
                "Expected tip to be {:?}, but got {:?}",
                expected_tip, txn.tip
            )
        );

        Ok(Self {})
    }
}
