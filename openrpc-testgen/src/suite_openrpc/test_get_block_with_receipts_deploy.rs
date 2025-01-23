use std::{path::PathBuf, str::FromStr};

use crate::{
    assert_result,
    utils::v7::{
        accounts::account::{starknet_keccak, Account, ConnectedAccount},
        contract::factory::ContractFactory,
        endpoints::{
            declare_contract::get_compiled_contract,
            errors::{CallError, OpenRpcTestGenError},
            utils::wait_for_sent_transaction,
        },
        providers::provider::Provider,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{
    BlockId, BlockStatus, BlockTag, BroadcastedInvokeTxn, BroadcastedTxn, DaMode, InvokeTxn,
    PriceUnit, TransactionAndReceipt, Txn, TxnFinalityStatus, TxnReceipt,
};
use t9n::txn_validation::invoke::verify_invoke_v3_signature;

const STRK_GAS_PRICE: Felt = Felt::from_hex_unchecked("0xa");
const STRK_BLOB_GAS_PRICE: Felt = Felt::from_hex_unchecked("0x14");
const GAS_PRICE: Felt = Felt::from_hex_unchecked("0x1e");
const BLOB_GAS_PRICE: Felt = Felt::from_hex_unchecked("0x28");
const DEPLOY_TXN_GAS: u64 = 706;
const DEPLOY_TXN_GAS_PRICE: u128 = 15;
const STRK_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D");
const UDC_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf");
const SEQUENCER_ADDRESS: Felt = Felt::from_hex_unchecked("0x123");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl15_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl15_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let sender = test_input.random_paymaster_account.random_accounts()?;
        let chain_id = sender.provider().chain_id().await?;

        let declare_result = sender
            .declare_v3(flattened_sierra_class, compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declare_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let factory = ContractFactory::new(declare_result.class_hash, sender.clone());
        let mut salt_buffer = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut salt_buffer[1..]);
        let salt = Felt::from_bytes_be(&salt_buffer);
        let unique = true;
        let constructor_calldata = vec![];
        let sender_nonce = sender.get_nonce().await?;

        let estimate_fee = factory
            .deploy_v3(constructor_calldata.clone(), salt, unique)
            .estimate_fee()
            .await?;

        let deploy_request = factory
            .deploy_v3(constructor_calldata.clone(), salt, unique)
            .gas(DEPLOY_TXN_GAS)
            .gas_price(DEPLOY_TXN_GAS_PRICE)
            .prepare_execute()
            .await?
            .get_invoke_request(false, false)
            .await?;

        let signature = deploy_request.clone().signature;

        let (valid_signature, deploy_hash) =
            verify_invoke_v3_signature(&deploy_request, None, chain_id.to_hex_string().as_str())?;

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

        let block_with_receipts = test_input
            .random_paymaster_account
            .provider()
            .get_block_with_receipts(BlockId::Tag(BlockTag::Latest))
            .await;

        let deployment_receipt = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_receipt(deploy_result.transaction_hash)
            .await?;

        let deployed_contract_address = match &deployment_receipt {
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

        let result = block_with_receipts.is_ok();
        assert_result!(result);

        let block_with_receipts = block_with_receipts?;

        assert_result!(
            block_with_receipts.transactions.len() == 1,
            format!(
                "Expected transactions amount to be {}, got {}",
                1,
                block_with_receipts.transactions.len()
            )
        );

        assert_result!(
            block_with_receipts.status == BlockStatus::AcceptedOnL2,
            format!(
                "Expected block status to be {:?}, but got {:?}.",
                BlockStatus::AcceptedOnL2,
                block_with_receipts.status
            )
        );

        let block_hash_and_number = test_input
            .random_paymaster_account
            .provider()
            .block_hash_and_number()
            .await?;

        let block_header = block_with_receipts.block_header;
        assert_result!(
            block_header.block_hash == block_hash_and_number.block_hash,
            format!(
                "Expected block hash to be {}, but got {}.",
                block_header.block_hash, block_hash_and_number.block_hash
            )
        );

        assert_result!(
            block_header.block_number == block_hash_and_number.block_number,
            format!(
                "Expected block number to be {}, but got {}.",
                block_header.block_number, block_hash_and_number.block_number
            )
        );

        assert_result!(
            block_header.l1_data_gas_price.price_in_fri == STRK_BLOB_GAS_PRICE,
            format!(
                "Expected L1 data gas price in FRI to be {}, but got {}.",
                block_header.l1_data_gas_price.price_in_fri, STRK_BLOB_GAS_PRICE
            )
        );

        assert_result!(
            block_header.l1_data_gas_price.price_in_wei == BLOB_GAS_PRICE,
            format!(
                "Expected L1 data gas price in WEI to be {}, but got {}.",
                block_header.l1_data_gas_price.price_in_wei, BLOB_GAS_PRICE
            )
        );

        assert_result!(
            block_header.l1_gas_price.price_in_fri == STRK_GAS_PRICE,
            format!(
                "Expected L1 gas price in FRI to be {}, but got {}.",
                block_header.l1_gas_price.price_in_fri, STRK_GAS_PRICE
            )
        );

        assert_result!(
            block_header.l1_gas_price.price_in_wei == GAS_PRICE,
            format!(
                "Expected L1 gas price in WEI to be {}, but got {}.",
                block_header.l1_gas_price.price_in_wei, GAS_PRICE
            )
        );

        let TransactionAndReceipt {
            transaction,
            receipt,
        } = block_with_receipts.transactions.first().ok_or_else(|| {
            OpenRpcTestGenError::Other("Transaction not found in block with receipts".to_string())
        })?;

        let deploy_receipt = match receipt {
            TxnReceipt::Invoke(deploy_receipt) => deploy_receipt,
            _ => {
                return Err(OpenRpcTestGenError::UnexpectedTxnType(
                    "Expected Deploy Receipt.".to_string(),
                ));
            }
        };

        let deploy_tx = match transaction {
            Txn::Invoke(deploy_tx) => match deploy_tx {
                InvokeTxn::V3(v3_tx) => v3_tx,
                _ => {
                    return Err(OpenRpcTestGenError::UnexpectedTxnType(
                        "Expected Invoke V3 Transaction.".to_string(),
                    ));
                }
            },
            _ => {
                return Err(OpenRpcTestGenError::UnexpectedTxnType(
                    "Expected Invoke Transaction.".to_string(),
                ));
            }
        };

        // Deploy Txn
        assert_result!(
            deploy_tx.account_deployment_data.is_empty(),
            "Expected account deployment data to be empty, but it was not."
        );

        let deploy_calldata = deploy_tx.calldata.clone();
        assert_result!(
            deploy_calldata.len() == 8,
            format!(
                "Expected calldata length to be 8, but got {}.",
                deploy_calldata.len()
            )
        );

        let deploy_calldata_calls_amount = *deploy_calldata
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        assert_result!(
            deploy_calldata_calls_amount == Felt::ONE,
            format!(
                "Expected calldata calls amount to be {}, but got {}.",
                Felt::ONE,
                deploy_calldata_calls_amount
            )
        );

        let deploy_calldata_udc = *deploy_calldata
            .get(1)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        assert_result!(
            deploy_calldata_udc == UDC_ADDRESS,
            format!(
                "Expected UDC address in calldata to be {}, but got {}.",
                UDC_ADDRESS, deploy_calldata_udc
            )
        );

        let keccak_deploy_account = starknet_keccak("deployContract".as_bytes());
        let deploy_calldata_keccak = *deploy_calldata
            .get(2)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        assert_result!(
            deploy_calldata_keccak == keccak_deploy_account,
            format!(
                "Expected keccak hash in calldata to be {}, but got {}.",
                keccak_deploy_account, deploy_calldata_keccak
            )
        );

        let calldata_fourth = *deploy_calldata.get(3).ok_or_else(|| {
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

        let deploy_calldata_class_hash = *deploy_calldata
            .get(4)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        assert_result!(
            deploy_calldata_class_hash == declare_result.class_hash,
            format!(
                "Expected class hash in calldata to be {}, but got {}.",
                declare_result.class_hash, deploy_calldata_class_hash
            )
        );

        let deploy_calldata_salt = *deploy_calldata
            .get(5)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        assert_result!(
            deploy_calldata_salt == salt,
            format!(
                "Expected salt in calldata to be {}, but got {}.",
                salt, deploy_calldata_salt
            )
        );

        let deploy_calldata_unique = *deploy_calldata
            .get(6)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        let unique_hex = match unique {
            true => Felt::ONE,
            false => Felt::ZERO,
        };

        assert_result!(
            deploy_calldata_unique == unique_hex,
            format!(
                "Expected unique value in calldata to be {}, but got {}.",
                unique_hex, deploy_calldata_unique
            )
        );

        let deploy_calldata_constructor_calldata_length = *deploy_calldata
            .get(7)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        let constructor_calldata_len_felt =
            Felt::from_dec_str(&constructor_calldata.len().to_string())?;

        assert_result!(
            deploy_calldata_constructor_calldata_length == constructor_calldata_len_felt,
            format!(
                "Expected constructor calldata length to be {}, but got {}.",
                constructor_calldata_len_felt, deploy_calldata_constructor_calldata_length
            )
        );

        assert_result!(
            deploy_tx.fee_data_availability_mode == DaMode::L1,
            format!(
                "Expected fee data availability mode to be {:?}, but got {:?}.",
                DaMode::L1,
                deploy_tx.fee_data_availability_mode
            )
        );

        assert_result!(
            deploy_tx.nonce == sender_nonce,
            format!(
                "Expected nonce to be {:?}, but got {:?}.",
                sender_nonce, deploy_tx.nonce
            )
        );

        assert_result!(
            deploy_tx.nonce_data_availability_mode == DaMode::L1,
            format!(
                "Expected nonce data availability mode to be {:?}, but got {:?}.",
                DaMode::L1,
                deploy_tx.nonce_data_availability_mode
            )
        );

        assert_result!(
            deploy_tx.paymaster_data.is_empty(),
            format!(
                "Expected paymaster data to be empty, but it was not. Got: {:?}",
                deploy_tx.paymaster_data
            )
        );

        let sender_address = sender.address();
        assert_result!(
            deploy_tx.sender_address == sender_address,
            format!(
                "Expected sender address to be {:?}, but got {:?}.",
                sender_address, deploy_tx.sender_address
            )
        );

        assert_result!(
            valid_signature,
            format!("Invalid signature, checked by t9n.",)
        );

        assert_result!(
            deploy_tx.signature == signature,
            format!(
                "Expected signature: {:?}, got {:?}",
                signature, deploy_tx.signature
            )
        );

        assert_result!(
            deploy_receipt.common_receipt_properties.transaction_hash
                == deploy_result.transaction_hash,
            format!(
                "Expected declare transaction hash: {:?}, but got {:?}",
                deploy_result.transaction_hash,
                deploy_receipt.common_receipt_properties.transaction_hash
            )
        );

        let expected_tip = Felt::ZERO;
        assert_result!(
            deploy_tx.tip == expected_tip,
            format!(
                "Expected tip to be {:?}, but got {:?}",
                expected_tip, deploy_tx.tip
            )
        );

        let deploy_txn_gas_hex = Felt::from_dec_str(&DEPLOY_TXN_GAS.to_string())?.to_hex_string();
        assert_result!(
            deploy_tx.resource_bounds.l1_gas.max_amount == deploy_txn_gas_hex,
            format!(
                "Expected l1 gas max amount to be {:?}, but got {:?}",
                deploy_txn_gas_hex, deploy_tx.resource_bounds.l1_gas.max_amount
            )
        );

        let deploy_txn_gas_price_hex =
            Felt::from_dec_str(&DEPLOY_TXN_GAS_PRICE.to_string())?.to_hex_string();
        assert_result!(
            deploy_tx.resource_bounds.l1_gas.max_price_per_unit == deploy_txn_gas_price_hex,
            format!(
                "Expected l1 gas max price per unit
                 to be {:?}, but got {:?}",
                deploy_txn_gas_price_hex, deploy_tx.resource_bounds.l1_gas.max_price_per_unit
            )
        );

        let expected_l2_gas_max_amount = Felt::ZERO.to_hex_string();
        assert_result!(
            deploy_tx.resource_bounds.l2_gas.max_amount == expected_l2_gas_max_amount,
            format!(
                "Expected l2 gas max amount to be {:?}, but got {:?}",
                expected_l2_gas_max_amount, deploy_tx.resource_bounds.l2_gas.max_amount
            )
        );

        let expected_l2_gas_max_price_per_unit = Felt::ZERO.to_hex_string();
        assert_result!(
            deploy_tx.resource_bounds.l2_gas.max_price_per_unit
                == expected_l2_gas_max_price_per_unit,
            format!(
                "Expected l2 gas max price per unit
                 to be {:?}, but got {:?}",
                expected_l2_gas_max_price_per_unit,
                deploy_tx.resource_bounds.l2_gas.max_price_per_unit
            )
        );

        // Deploy receipt
        let actual_fee = deploy_receipt.common_receipt_properties.actual_fee.clone();

        assert_result!(
            actual_fee.amount == estimate_fee.overall_fee,
            format!(
                "Expected overall fee to be {:?}, but got {:?}",
                estimate_fee.overall_fee, actual_fee.unit
            )
        );

        assert_result!(
            actual_fee.unit == PriceUnit::Fri,
            format!(
                "Expected price unit to be {:?}, but got {:?}",
                PriceUnit::Fri,
                actual_fee.unit
            )
        );

        let events = deploy_receipt.common_receipt_properties.events.clone();

        assert_result!(
            events.len() == 2,
            format!("Expected 2 events, but got {:#?}", events.len())
        );

        let first_event = deploy_receipt
            .common_receipt_properties
            .events
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Event missing".to_string()))?;

        assert_result!(
            first_event.from_address == UDC_ADDRESS,
            format!(
                "Expected event from address to be {:?}, but got {:?}",
                UDC_ADDRESS, first_event.from_address
            )
        );

        let first_event_data_first = *first_event
            .data
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing first event data".to_string()))?;

        assert_result!(
            first_event_data_first == deployed_contract_address,
            format!(
                "Expected first event data to be {:?}, got {:?}",
                deployed_contract_address, first_event_data_first
            )
        );

        let first_event_data_second = *first_event
            .data
            .get(1)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing secpnd event data".to_string()))?;

        assert_result!(
            first_event_data_second == sender_address,
            format!(
                "Expected second event data to be {:?}, got {:?}",
                sender_address, first_event_data_second
            )
        );

        let first_event_data_third = *first_event
            .data
            .get(2)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing third event data".to_string()))?;

        assert_result!(
            first_event_data_third == unique_hex,
            format!(
                "Expected third event data to be {:?}, got {:?}",
                unique_hex, first_event_data_third
            )
        );

        let first_event_data_fourth = *first_event
            .data
            .get(3)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing fourth event data".to_string()))?;

        assert_result!(
            first_event_data_fourth == declare_result.class_hash,
            format!(
                "Expected fourth event data to be {:?}, got {:?}",
                declare_result.class_hash, first_event_data_fourth
            )
        );

        let first_event_data_fifth = *first_event
            .data
            .get(4)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing fifth event data".to_string()))?;

        assert_result!(
            first_event_data_fifth == constructor_calldata_len_felt,
            format!(
                "Expected fifth event data to be {:?}, got {:?}",
                constructor_calldata_len_felt, first_event_data_fifth
            )
        );

        let first_event_data_sixth = *first_event
            .data
            .get(5)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing sixth event data".to_string()))?;

        assert_result!(
            first_event_data_sixth == salt,
            format!(
                "Expected sixth event data to be {:?}, got {:?}",
                salt, first_event_data_sixth
            )
        );

        let first_event_keys_first = *first_event
            .keys
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing first event key".to_string()))?;
        let keccak_contract_deployed = starknet_keccak("ContractDeployed".as_bytes());

        assert_result!(
            first_event_keys_first == keccak_contract_deployed,
            format!(
                "Invalid keccak in event keys, expected {:?}, got {:?}",
                keccak_contract_deployed, first_event_keys_first
            )
        );

        let second_event = deploy_receipt
            .common_receipt_properties
            .events
            .get(1)
            .ok_or_else(|| OpenRpcTestGenError::Other("Event missing".to_string()))?;

        assert_result!(
            second_event.from_address == STRK_ADDRESS,
            format!(
                "Expected event from address to be {:?}, got {:?}",
                STRK_ADDRESS, second_event.from_address
            )
        );

        let second_event_data_first = *second_event
            .data
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing second event data".to_string()))?;

        assert_result!(
            second_event_data_first == estimate_fee.overall_fee,
            format!(
                "Invalid fee amount in event data, expected {}, got {:?}",
                estimate_fee.overall_fee, second_event_data_first
            )
        );

        let second_event_data_second = *second_event
            .data
            .get(1)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing second event data".to_string()))?;

        assert_result!(
            second_event_data_second == Felt::ZERO,
            format!(
                "Invalid fee amount in event data, expected {}, got {:?}",
                Felt::ZERO,
                second_event_data_second
            )
        );

        let second_event_keys_first = *second_event
            .keys
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing second event key".to_string()))?;
        let keccak_transfer = starknet_keccak("Transfer".as_bytes());
        assert_result!(
            second_event_keys_first == keccak_transfer,
            format!(
                "Invalid keccak transfer in event keys, expected {}, got {:?}",
                keccak_transfer, second_event_keys_first
            )
        );

        let second_event_keys_second = *second_event
            .keys
            .get(1)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing second event key".to_string()))?;
        assert_result!(
            second_event_keys_second == sender_address,
            format!(
                "Invalid sender address in event keys, expected {}, got {:?}",
                sender_address, second_event_keys_second
            )
        );

        let second_event_keys_third = *second_event
            .keys
            .get(2)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing second event key".to_string()))?;
        assert_result!(
            second_event_keys_third == SEQUENCER_ADDRESS,
            format!(
                "Invalid sequencer address in event keys, expected {}, got {:?}",
                SEQUENCER_ADDRESS, second_event_keys_third
            )
        );

        let finality_status = deploy_receipt
            .common_receipt_properties
            .finality_status
            .clone();

        assert_result!(
            finality_status == TxnFinalityStatus::L2,
            format!(
                "Invalid finality status, expected {:?}, got {:?}",
                TxnFinalityStatus::L2,
                finality_status
            )
        );

        assert_result!(
            deploy_receipt
                .common_receipt_properties
                .messages_sent
                .is_empty(),
            "Expected no messages sent"
        );

        assert_result!(
            deploy_receipt.common_receipt_properties.transaction_hash
                == deploy_result.transaction_hash,
            format!(
                "Invalid transaction hash, expected {}, got {}",
                deploy_result.transaction_hash,
                deploy_receipt.common_receipt_properties.transaction_hash
            )
        );

        let execution_status = match deploy_receipt.common_receipt_properties.anon.clone() {
            starknet_types_rpc::Anonymous::Successful(status) => status.execution_status,
            _ => {
                return Err(OpenRpcTestGenError::Other(
                    "Unexpected execution status type.".to_string(),
                ));
            }
        };

        let expected_execution_status = "SUCCEEDED".to_string();

        assert_result!(
            execution_status == expected_execution_status,
            format!(
                "Expected execution status to be {:?}, got {:?}",
                expected_execution_status, execution_status
            )
        );

        Ok(Self {})
    }
}
