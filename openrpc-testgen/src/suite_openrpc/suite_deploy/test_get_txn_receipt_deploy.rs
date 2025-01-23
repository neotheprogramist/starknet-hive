use crate::assert_result;
use crate::utils::v7::accounts::account::{starknet_keccak, Account, ConnectedAccount};
use crate::utils::v7::contract::factory::ContractFactory;
use crate::utils::v7::endpoints::errors::CallError;
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::provider::Provider;
use crate::RandomizableAccountsTrait;
use crate::{utils::v7::endpoints::errors::OpenRpcTestGenError, RunnableTrait};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{PriceUnit, TxnFinalityStatus, TxnReceipt};

const STRK_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D");
const SEQUENCER_ADDRESS: Felt = Felt::from_hex_unchecked("0x123");
const UDC_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteDeploy;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let sender = test_input.random_paymaster_account.random_accounts()?;
        let sender_address = sender.address();

        let factory = ContractFactory::new(test_input.declaration_result.class_hash, sender);
        let mut salt_buffer = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut salt_buffer[1..]);
        let salt = Felt::from_bytes_be(&salt_buffer);
        let unique = true;
        let constructor_calldata = vec![];
        let estimate_fee = factory
            .deploy_v3(constructor_calldata.clone(), salt, unique)
            .estimate_fee()
            .await?;

        let invoke_result = factory
            .deploy_v3(constructor_calldata.clone(), salt, unique)
            .send()
            .await?;

        wait_for_sent_transaction(
            invoke_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let receipt = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_receipt(invoke_result.transaction_hash)
            .await;

        let result = receipt.is_ok();

        assert_result!(result);

        let receipt = match receipt? {
            TxnReceipt::Invoke(receipt) => receipt,
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
            common_receipt_properties.transaction_hash == invoke_result.transaction_hash,
            format!(
                "Expected transaction hash: {:?}, actual: {:?}",
                invoke_result.transaction_hash, common_receipt_properties.transaction_hash
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

        let events = common_receipt_properties.events.clone();
        assert_result!(
            events.len() == 2,
            format!("Expected 2 event, got {}", events.len())
        );

        let first_event = events
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Event not found".to_string()))?;
        assert_result!(
            first_event.from_address == UDC_ADDRESS,
            format!(
                "Expected event from address to be {:?}, got {:?}",
                UDC_ADDRESS, first_event.from_address
            )
        );

        assert_result!(
            first_event.data.len() == 6,
            format!(
                "Expected first event to contain 6 data items, got {}",
                first_event.data.len()
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

        let unique_hex = match unique {
            true => Felt::ONE,
            false => Felt::ZERO,
        };
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
        let expected_class_hash = test_input.declaration_result.class_hash;
        assert_result!(
            first_event_data_fourth == expected_class_hash,
            format!(
                "Expected fourth event data to be {:?}, got {:?}",
                expected_class_hash, first_event_data_fourth
            )
        );

        let first_event_data_fifth = *first_event
            .data
            .get(4)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing fifth event data".to_string()))?;
        let constructor_calldata_len_felt =
            Felt::from_dec_str(&constructor_calldata.len().to_string())?;
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

        let second_event = common_receipt_properties
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
        Ok(Self {})
    }
}
