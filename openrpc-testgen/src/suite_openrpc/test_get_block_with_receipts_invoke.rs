use crate::{
    assert_result,
    utils::v7::{
        accounts::{
            account::{starknet_keccak, Account, ConnectedAccount},
            call::Call,
        },
        endpoints::{
            errors::OpenRpcTestGenError,
            utils::{get_selector_from_name, wait_for_sent_transaction},
        },
        providers::provider::Provider,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
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
const INVOKE_TXN_GAS: u64 = 994;
const INVOKE_TXN_GAS_PRICE: u128 = 15;
const STRK_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D");
const SEQUENCER_ADDRESS: Felt = Felt::from_hex_unchecked("0x123");
const ETH_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x49D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let recipient_address =
            Felt::from_hex("0xdeadbeefD4ED6B33F99674BD3FCC84644DDD6B96F7C741B1562B82F9E00B33F")?;

        let transfer_amount = Felt::from_hex("0x123")?;
        let transfer_calldata = vec![recipient_address, transfer_amount, Felt::ZERO];
        let sender = test_input.random_paymaster_account.random_accounts()?;
        let sender_nonce = sender.get_nonce().await?;

        let estimate_fee = sender
            .execute_v3(vec![Call {
                to: ETH_ADDRESS,
                selector: get_selector_from_name("transfer")?,
                calldata: transfer_calldata.clone(),
            }])
            .estimate_fee()
            .await?;

        let invoke_request = sender
            .execute_v3(vec![Call {
                to: ETH_ADDRESS,
                selector: get_selector_from_name("transfer")?,
                calldata: transfer_calldata.clone(),
            }])
            .prepare()
            .await?
            .get_invoke_request(false, false)
            .await?;

        let signature = invoke_request.clone().signature;

        let (valid_signature, invoke_hash) = verify_invoke_v3_signature(
            &invoke_request,
            None,
            sender.provider().chain_id().await?.to_hex_string().as_str(),
        )?;

        let invoke_result = sender
            .provider()
            .add_invoke_transaction(BroadcastedTxn::Invoke(BroadcastedInvokeTxn::V3(
                invoke_request,
            )))
            .await?;

        wait_for_sent_transaction(
            invoke_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        assert_result!(
            invoke_result.transaction_hash == invoke_hash,
            format!(
                "Exptected transaction hash to be {:?}, got {:?}",
                invoke_hash, invoke_result.transaction_hash
            )
        );

        let block_with_receipts = test_input
            .random_paymaster_account
            .provider()
            .get_block_with_receipts(BlockId::Tag(BlockTag::Latest))
            .await;

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

        let invoke_receipt = match receipt {
            TxnReceipt::Invoke(invoke_receipt) => invoke_receipt,
            _ => {
                return Err(OpenRpcTestGenError::UnexpectedTxnType(
                    "Expected Invoke Receipt.".to_string(),
                ));
            }
        };

        let invoke_tx = match transaction {
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

        // Invoke Txn
        assert_result!(
            invoke_tx.account_deployment_data.is_empty(),
            format!(
                "Expected account deployment data to be empty, but it was not. Got: {:?}",
                invoke_tx.account_deployment_data
            )
        );

        let invoke_calldata = invoke_tx.calldata.clone();
        assert_result!(
            invoke_calldata.len() == 7,
            format!(
                "Expected calldata length to be 7, but got {}.",
                invoke_calldata.len()
            )
        );

        let invoke_calldata_calls_amount = *invoke_calldata
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        assert_result!(
            invoke_calldata_calls_amount == Felt::ONE,
            format!(
                "Expected calldata calls amount to be {:?}, but got {:?}.",
                Felt::ONE,
                invoke_calldata_calls_amount
            )
        );

        let invoke_calldata_eth_address = *invoke_calldata
            .get(1)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        assert_result!(
            invoke_calldata_eth_address == ETH_ADDRESS,
            format!(
                "Expected UDC address in calldata to be {:?}, but got {:?}.",
                ETH_ADDRESS, invoke_calldata_eth_address
            )
        );

        let keccak_transfer = starknet_keccak("transfer".as_bytes());
        let invoke_calldata_keccak = *invoke_calldata
            .get(2)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        assert_result!(
            invoke_calldata_keccak == keccak_transfer,
            format!(
                "Expected keccak hash in calldata to be {:?}, but got {:?}.",
                keccak_transfer, invoke_calldata_keccak
            )
        );

        let invoke_calldata_transfer_calldata_len = *invoke_calldata
            .get(3)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        let transfer_calldata_len_hex = Felt::from_dec_str(&transfer_calldata.len().to_string())?;
        assert_result!(
            invoke_calldata_transfer_calldata_len == transfer_calldata_len_hex,
            format!(
                "Expected transfer calldata length in calldata to be {:?}, but got {:?}.",
                transfer_calldata_len_hex, invoke_calldata_transfer_calldata_len
            )
        );

        let invoke_calldata_recipient_address = *invoke_calldata
            .get(4)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        assert_result!(
            invoke_calldata_recipient_address == recipient_address,
            format!(
                "Expected recipient address in calldata to be {:?}, but got {:?}.",
                recipient_address, invoke_calldata_recipient_address
            )
        );

        let invoke_calldata_transfer_amount = *invoke_calldata
            .get(5)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        assert_result!(
            invoke_calldata_transfer_amount == transfer_amount,
            format!(
                "Expected transfer amount in calldata to be {:?}, but got {:?}.",
                transfer_amount, invoke_calldata_transfer_amount
            )
        );

        let invoke_calldata_transfer_amount_2 = *invoke_calldata
            .get(6)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing calldata".to_string()))?;

        assert_result!(
            invoke_calldata_transfer_amount_2 == Felt::ZERO,
            format!(
                "Expected transfer amount in calldata to be {:?}, but got {:?}.",
                Felt::ZERO,
                invoke_calldata_transfer_amount_2
            )
        );

        assert_result!(
            invoke_tx.fee_data_availability_mode == DaMode::L1,
            format!(
                "Expected fee data availability mode to be {:?}, but got {:?}.",
                DaMode::L1,
                invoke_tx.fee_data_availability_mode
            )
        );

        assert_result!(
            invoke_tx.nonce == sender_nonce,
            format!(
                "Expected nonce to be {:?}, but got {:?}.",
                sender_nonce, invoke_tx.nonce
            )
        );

        assert_result!(
            invoke_tx.nonce_data_availability_mode == DaMode::L1,
            format!(
                "Expected nonce data availability mode to be {:?}, but got {:?}.",
                DaMode::L1,
                invoke_tx.nonce_data_availability_mode
            )
        );

        assert_result!(
            invoke_tx.paymaster_data.is_empty(),
            format!(
                "Expected paymaster data to be empty, but it was not. Got: {:?}",
                invoke_tx.paymaster_data
            )
        );

        let sender_address = sender.address();
        assert_result!(
            invoke_tx.sender_address == sender_address,
            format!(
                "Expected sender address to be {:?}, but got {:?}.",
                sender_address, invoke_tx.sender_address
            )
        );

        assert_result!(
            valid_signature,
            format!("Invalid signature, checked by t9n.",)
        );

        assert_result!(
            invoke_tx.signature == signature,
            format!(
                "Expected signature: {:?}, got {:?}",
                signature, invoke_tx.signature
            )
        );

        assert_result!(
            invoke_receipt.common_receipt_properties.transaction_hash
                == invoke_result.transaction_hash,
            format!(
                "Expected declare transaction hash: {:?}, but got {:?}",
                invoke_result.transaction_hash,
                invoke_receipt.common_receipt_properties.transaction_hash
            )
        );

        let expected_tip = Felt::ZERO;
        assert_result!(
            invoke_tx.tip == expected_tip,
            format!(
                "Expected tip to be {:?}, but got {:?}",
                expected_tip, invoke_tx.tip
            )
        );

        let invoke_tx_gas_hex = Felt::from_dec_str(&INVOKE_TXN_GAS.to_string())?.to_hex_string();
        assert_result!(
            invoke_tx.resource_bounds.l1_gas.max_amount == invoke_tx_gas_hex,
            format!(
                "Expected l1 gas max amount to be {:?}, but got {:?}",
                invoke_tx_gas_hex, invoke_tx.resource_bounds.l1_gas.max_amount
            )
        );

        let invoke_txn_gas_price_hex =
            Felt::from_dec_str(&INVOKE_TXN_GAS_PRICE.to_string())?.to_hex_string();
        assert_result!(
            invoke_tx.resource_bounds.l1_gas.max_price_per_unit == invoke_txn_gas_price_hex,
            format!(
                "Expected l1 gas max price per unit
                 to be {:?}, but got {:?}",
                invoke_txn_gas_price_hex, invoke_tx.resource_bounds.l1_gas.max_price_per_unit
            )
        );

        let expected_l2_gas_max_amount = Felt::ZERO.to_hex_string();
        assert_result!(
            invoke_tx.resource_bounds.l2_gas.max_amount == expected_l2_gas_max_amount,
            format!(
                "Expected l2 gas max amount to be {:?}, but got {:?}",
                expected_l2_gas_max_amount, invoke_tx.resource_bounds.l2_gas.max_amount
            )
        );

        let expected_l2_gas_max_price_per_unit = Felt::ZERO.to_hex_string();
        assert_result!(
            invoke_tx.resource_bounds.l2_gas.max_price_per_unit
                == expected_l2_gas_max_price_per_unit,
            format!(
                "Expected l2 gas max price per unit
                 to be {:?}, but got {:?}",
                expected_l2_gas_max_price_per_unit,
                invoke_tx.resource_bounds.l2_gas.max_price_per_unit
            )
        );

        // Invoke receipt
        let actual_fee = invoke_receipt.common_receipt_properties.actual_fee.clone();

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

        let events = invoke_receipt.common_receipt_properties.events.clone();

        assert_result!(
            events.len() == 2,
            format!("Expected 2 events, but got {:#?}", events.len())
        );

        let first_event = invoke_receipt
            .common_receipt_properties
            .events
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Event missing".to_string()))?;

        assert_result!(
            first_event.from_address == ETH_ADDRESS,
            format!(
                "Expected event from address to be {:?}, but got {:?}",
                ETH_ADDRESS, first_event.from_address
            )
        );

        let first_event_data_first = *first_event
            .data
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing first event data".to_string()))?;

        assert_result!(
            first_event_data_first == transfer_amount,
            format!(
                "Expected first event first data to be {:?}, got {:?}",
                transfer_amount, first_event_data_first
            )
        );

        let first_event_data_second = *first_event
            .data
            .get(1)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing secpnd event data".to_string()))?;

        assert_result!(
            first_event_data_second == Felt::ZERO,
            format!(
                "Expected first event second data to be {:?}, got {:?}",
                Felt::ZERO,
                first_event_data_second
            )
        );

        let first_event_keys_first = *first_event
            .keys
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing first event key".to_string()))?;
        let keccak_transfer = starknet_keccak("Transfer".as_bytes());

        assert_result!(
            first_event_keys_first == keccak_transfer,
            format!(
                "Invalid keccak in event keys, expected {:?}, got {:?}",
                keccak_transfer, first_event_keys_first
            )
        );

        let first_event_keys_second = *first_event
            .keys
            .get(1)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing first event key".to_string()))?;

        assert_result!(
            first_event_keys_second == sender_address,
            format!(
                "Invalid sender address in event keys, expected {:?}, got {:?}",
                sender_address, first_event_keys_second
            )
        );

        let first_event_keys_third = *first_event
            .keys
            .get(2)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing first event key".to_string()))?;

        assert_result!(
            first_event_keys_third == recipient_address,
            format!(
                "Invalid recipient address in event keys, expected {:?}, got {:?}",
                recipient_address, first_event_keys_third
            )
        );

        let second_event = invoke_receipt
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

        let finality_status = invoke_receipt
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
            invoke_receipt
                .common_receipt_properties
                .messages_sent
                .is_empty(),
            "Expected no messages sent"
        );

        assert_result!(
            invoke_receipt.common_receipt_properties.transaction_hash
                == invoke_result.transaction_hash,
            format!(
                "Invalid transaction hash, expected {}, got {}",
                invoke_result.transaction_hash,
                invoke_receipt.common_receipt_properties.transaction_hash
            )
        );

        let execution_status = match invoke_receipt.common_receipt_properties.anon.clone() {
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
