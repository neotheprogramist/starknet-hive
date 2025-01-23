use crate::assert_result;
use crate::utils::v7::accounts::account::{starknet_keccak, Account, ConnectedAccount};
use crate::utils::v7::endpoints::declare_contract::get_compiled_contract;
use crate::utils::v7::endpoints::errors::CallError;
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::provider::Provider;
use crate::RandomizableAccountsTrait;
use crate::{utils::v7::endpoints::errors::OpenRpcTestGenError, RunnableTrait};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{PriceUnit, TxnFinalityStatus, TxnReceipt};
use std::path::PathBuf;
use std::str::FromStr;

const STRK_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D");
const SEQUENCER_ADDRESS: Felt = Felt::from_hex_unchecked("0x123");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl19_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl19_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let sender = test_input.random_paymaster_account.random_accounts()?;
        let sender_address = sender.address();

        let estimate_fee = sender
            .declare_v3(flattened_sierra_class.clone(), compiled_class_hash)
            .estimate_fee()
            .await?;

        let declaration_result = sender
            .declare_v3(flattened_sierra_class, compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declaration_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let receipt = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_receipt(declaration_result.transaction_hash)
            .await;

        let result = receipt.is_ok();

        assert_result!(result);

        let receipt = match receipt? {
            TxnReceipt::Declare(receipt) => receipt,
            _ => {
                return Err(OpenRpcTestGenError::CallError(
                    CallError::UnexpectedReceiptType,
                ))
            }
        };

        let common_receipt_properties = receipt.common_receipt_properties;
        let actual_fee = common_receipt_properties.actual_fee;
        assert_result!(
            actual_fee.amount == estimate_fee.overall_fee,
            format!(
                "Actual fee expected: {:?}, actual: {:?}",
                estimate_fee.overall_fee, actual_fee.amount
            )
        );

        let expected_unit = PriceUnit::Fri;
        assert_result!(
            actual_fee.unit == expected_unit,
            format!(
                "Actual fee unit expected: {:?}, actual: {:?}",
                expected_unit, actual_fee.unit
            )
        );

        let expected_finality_status = TxnFinalityStatus::L2;
        assert_result!(
            common_receipt_properties.finality_status == expected_finality_status,
            format!(
                "Expected finality status: {:?}, actual: {:?}",
                expected_finality_status, common_receipt_properties.finality_status
            )
        );

        assert_result!(
            common_receipt_properties.messages_sent.is_empty(),
            format!(
                "Expected no messages sent, actual: {:?}",
                common_receipt_properties.messages_sent
            )
        );

        assert_result!(
            common_receipt_properties.transaction_hash == declaration_result.transaction_hash,
            format!(
                "Expected transaction hash: {:?}, actual: {:?}",
                declaration_result.transaction_hash, common_receipt_properties.transaction_hash
            )
        );

        let execution_status = match common_receipt_properties.anon {
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

        let events = common_receipt_properties.events;
        assert_result!(
            events.len() == 1,
            format!("Expected 1 event, got {}", events.len())
        );

        let event = events
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Event not found".to_string()))?;
        assert_result!(event.from_address == STRK_ADDRESS);

        assert_result!(
            event.data.len() == 2,
            format!("Expected 2 data items, got {}", event.data.len())
        );

        let event_data_first = *event
            .data
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Event data not found".to_string()))?;
        assert_result!(
            event_data_first == estimate_fee.overall_fee,
            format!(
                "Expected event data to be {:?}, got {:?}",
                estimate_fee.overall_fee, event_data_first
            )
        );

        let event_data_second = *event
            .data
            .last()
            .ok_or_else(|| OpenRpcTestGenError::Other("Event data not found".to_string()))?;

        assert_result!(
            event_data_second == Felt::ZERO,
            format!(
                "Expected event data to be {:?}, got {:?}",
                Felt::ZERO,
                event_data_second
            )
        );

        assert_result!(
            event.keys.len() == 3,
            format!("Expected 3 keys, got {}", event.keys.len())
        );

        let event_key_first = *event
            .keys
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Event key not found".to_string()))?;
        let keccak_transfer = starknet_keccak("Transfer".as_bytes());

        assert_result!(
            event_key_first == keccak_transfer,
            format!(
                "Expected event key to be {:?}, got {:?}",
                keccak_transfer, event_key_first
            )
        );

        let event_key_second = *event
            .keys
            .get(1)
            .ok_or_else(|| OpenRpcTestGenError::Other("Event key not found".to_string()))?;

        assert_result!(
            event_key_second == sender_address,
            format!(
                "Expected event key to be {:?}, got {:?}",
                sender_address, event_key_second
            )
        );

        let event_key_third = *event
            .keys
            .last()
            .ok_or_else(|| OpenRpcTestGenError::Other("Event key not found".to_string()))?;

        assert_result!(
            event_key_third == SEQUENCER_ADDRESS,
            format!(
                "Expected event key to be {:?}, got {:?}",
                SEQUENCER_ADDRESS, event_key_third
            )
        );

        Ok(Self {})
    }
}
