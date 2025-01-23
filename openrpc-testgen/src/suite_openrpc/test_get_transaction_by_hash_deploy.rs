use std::path::PathBuf;
use std::str::FromStr;

use crate::utils::v7::accounts::account::{starknet_keccak, Account};
use crate::utils::v7::contract::factory::ContractFactory;
use crate::utils::v7::endpoints::declare_contract::get_compiled_contract;
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::{assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::{
        accounts::account::ConnectedAccount, endpoints::errors::OpenRpcTestGenError,
        providers::provider::Provider,
    },
    RunnableTrait,
};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BroadcastedInvokeTxn, BroadcastedTxn, DaMode, InvokeTxn, Txn};
use t9n::txn_validation::invoke::verify_invoke_v3_signature;

const UDC_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl18_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl18_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let declaration_result = test_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class, compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declaration_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let deployer_account = test_input.random_paymaster_account.random_accounts()?;
        let factory = ContractFactory::new(declaration_result.class_hash, deployer_account.clone());
        let constructor_calldata = vec![];
        let mut salt_buffer = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut salt_buffer[1..]);
        let salt = Felt::from_bytes_be(&salt_buffer);
        let unique = true;

        let sender_nonce = deployer_account.get_nonce().await?;

        let deploy_request = factory
            .deploy_v3(constructor_calldata.clone(), salt, unique)
            .prepare_execute()
            .await?
            .get_invoke_request(false, false)
            .await?;

        let signature = deploy_request.clone().signature;
        let (valid_signature, deploy_hash) = verify_invoke_v3_signature(
            &deploy_request,
            None,
            deployer_account
                .provider()
                .chain_id()
                .await?
                .to_hex_string()
                .as_str(),
        )?;

        let deploy_result = test_input
            .random_paymaster_account
            .provider()
            .add_invoke_transaction(BroadcastedTxn::Invoke(BroadcastedInvokeTxn::V3(
                deploy_request,
            )))
            .await?;

        wait_for_sent_transaction(
            deploy_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        assert_result!(
            deploy_result.transaction_hash == deploy_hash,
            format!(
                "Exptected transaction hash to be {:?}, got {:?}",
                deploy_hash, deploy_result.transaction_hash
            )
        );

        let txn = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_by_hash(deploy_result.transaction_hash)
            .await;

        let result = txn.is_ok();
        assert_result!(result);

        let txn = match txn? {
            Txn::Invoke(InvokeTxn::V3(txn)) => txn,
            _ => return Err(OpenRpcTestGenError::Other("Expected InvokeTxn".to_string())),
        };

        assert_result!(
            txn.account_deployment_data.is_empty(),
            format!(
                "Expected empty account deployment data, got {:#?}",
                txn.account_deployment_data
            )
        );

        assert_result!(
            txn.calldata.len() == 8,
            format!("Expected calldata len 8, got {:#?} ", txn.calldata.len())
        );

        let calldata_first = *txn.calldata.first().ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing first calldata element".to_string())
        })?;

        let calls_amount = Felt::ONE;
        assert_result!(
            calldata_first == calls_amount,
            format!(
                "Expected first calldata element to be {:#?}, got {:#?} ",
                calls_amount, calldata_first
            )
        );

        let calldata_second = *txn.calldata.get(1).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;

        assert_result!(
            calldata_second == UDC_ADDRESS,
            format!(
                "Expected second calldata element to be {:#?}, got {:#?}",
                UDC_ADDRESS, calldata_second
            )
        );

        let calldata_third = *txn.calldata.get(2).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;
        let keccak_deploy_contract = starknet_keccak("deployContract".as_bytes());

        assert_result!(
            calldata_third == keccak_deploy_contract,
            format!(
                "Expected third calldata element to be {:#?}, got {:#?}",
                keccak_deploy_contract, calldata_third
            )
        );

        // Calldata call length
        let calldata_fourth = *txn.calldata.get(3).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;
        let expected_calldata_call_length = Felt::from_hex("0x4")?;
        assert_result!(
            calldata_fourth == expected_calldata_call_length,
            format!(
                "Expected fourth calldata element to be {:#?}, got {:#?}",
                expected_calldata_call_length, calldata_fourth
            )
        );

        let calldata_fifth = *txn.calldata.get(4).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;

        assert_result!(
            calldata_fifth == declaration_result.class_hash,
            format!(
                "Expected fifth calldata element to be {:#?}, got {:#?}",
                declaration_result.class_hash, calldata_fifth
            )
        );

        let calldata_sixth = *txn.calldata.get(5).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;

        assert_result!(
            calldata_sixth == salt,
            format!(
                "Expected sixth calldata element to be {:#?}, got {:#?}",
                salt, calldata_sixth
            )
        );

        let calldata_seventh = *txn.calldata.get(6).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;

        let unique_hex = match unique {
            true => Felt::ONE,
            false => Felt::ZERO,
        };
        assert_result!(
            calldata_seventh == unique_hex,
            format!(
                "
            Expected seventh calldata element to be {:#?}, got {:#?}",
                unique_hex, calldata_seventh
            )
        );

        let calldata_eight = *txn.calldata.get(7).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;
        let contructor_calldata_len_hex =
            Felt::from_dec_str(&constructor_calldata.len().to_string())?;
        assert_result!(
            calldata_eight == contructor_calldata_len_hex,
            format!(
                "Expected eigth calldata element to be {:#?}, got {:#?}",
                contructor_calldata_len_hex, calldata_eight
            )
        );

        let expected_fee_damode = DaMode::L1;
        assert_result!(
            txn.fee_data_availability_mode == expected_fee_damode,
            format!(
                "Expected fee data availability mode to be {:#?}, got {:#?}",
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
                "Expected nonce to be {:#?}, got {:#?}",
                sender_nonce, txn.nonce
            )
        );

        let expected_nonce_damode = DaMode::L1;
        assert_result!(
            txn.nonce_data_availability_mode == expected_nonce_damode,
            format!(
                "Expected nonce data availability mode to be {:#?}, got {:#?}",
                expected_nonce_damode, txn.nonce_data_availability_mode
            )
        );

        assert_result!(
            txn.paymaster_data.is_empty(),
            format!(
                "Expected paymaster data to be empty, got {:#?}",
                txn.paymaster_data
            )
        );

        let l1_gas_max_amount = String::from("0x2c2");
        assert_result!(
            txn.resource_bounds.l1_gas.max_amount == l1_gas_max_amount,
            format!(
                "Expected l1 gas max amount to be {:#?}, got {:#?}",
                l1_gas_max_amount, txn.resource_bounds.l1_gas.max_amount
            )
        );

        let l1_gas_max_price_per_unit = String::from("0xf");
        assert_result!(
            txn.resource_bounds.l1_gas.max_price_per_unit == l1_gas_max_price_per_unit,
            format!(
                "Expected l1 gas max price per unit to be {:#?}, got {:#?}",
                l1_gas_max_price_per_unit, txn.resource_bounds.l1_gas.max_price_per_unit
            )
        );

        let l2_gas_max_amount = String::from("0x0");
        assert_result!(
            txn.resource_bounds.l2_gas.max_amount == l2_gas_max_amount,
            format!(
                "Expected l2 gas max amount to be {:#?}, got {:#?}",
                l2_gas_max_amount, txn.resource_bounds.l2_gas.max_amount
            )
        );

        let l2_gas_max_price_per_unit = String::from("0x0");
        assert_result!(
            txn.resource_bounds.l2_gas.max_price_per_unit == l2_gas_max_price_per_unit,
            format!(
                "Expected l2 gas max price per unit to be {:#?}, got {:#?}",
                l2_gas_max_price_per_unit, txn.resource_bounds.l2_gas.max_price_per_unit
            )
        );

        let sender_address = deployer_account.address();
        assert_result!(
            txn.sender_address == sender_address,
            format!(
                "Expected sender address to be {:#?}, got {:#?}",
                sender_address, txn.sender_address
            )
        );

        let expected_tip = Felt::from_hex("0x0")?;
        assert_result!(
            txn.tip == expected_tip,
            format!("Expected tip to be {:#?}, got {:#?}", expected_tip, txn.tip)
        );

        Ok(Self {})
    }
}
