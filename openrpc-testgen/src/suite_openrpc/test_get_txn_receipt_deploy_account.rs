use crate::assert_result;
use crate::utils::v7::accounts::account::{starknet_keccak, Account, ConnectedAccount};
use crate::utils::v7::accounts::call::Call;
use crate::utils::v7::accounts::creation::create::{create_account, AccountType};
use crate::utils::v7::accounts::deployment::deploy::{
    deploy_account, estimate_fee_deploy_account, DeployAccountVersion,
};
use crate::utils::v7::accounts::deployment::structs::{ValidatedWaitParams, WaitForTx};
use crate::utils::v7::endpoints::errors::CallError;
use crate::utils::v7::endpoints::utils::{get_selector_from_name, wait_for_sent_transaction};
use crate::utils::v7::providers::provider::Provider;
use crate::RandomizableAccountsTrait;
use crate::{utils::v7::endpoints::errors::OpenRpcTestGenError, RunnableTrait};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{PriceUnit, TxnFinalityStatus, TxnReceipt};

const STRK_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D");
const SEQUENCER_ADDRESS: Felt = Felt::from_hex_unchecked("0x123");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let account_data = create_account(
            test_input.random_paymaster_account.provider(),
            AccountType::Oz,
            Option::None,
            Some(test_input.account_class_hash),
        )
        .await?;

        let transfer_amount = Felt::from_hex("0xfffffffffffffff")?;

        let transfer_execution = test_input
            .random_paymaster_account
            .execute_v3(vec![Call {
                to: Felt::from_hex(
                    "0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D",
                )?,
                selector: get_selector_from_name("transfer")?,
                calldata: vec![account_data.address, transfer_amount, Felt::ZERO],
            }])
            .send()
            .await?;

        wait_for_sent_transaction(
            transfer_execution.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let wait_config = WaitForTx {
            wait: true,
            wait_params: ValidatedWaitParams::default(),
        };

        let estimate_fee = estimate_fee_deploy_account(
            test_input.random_paymaster_account.provider(),
            test_input.random_paymaster_account.chain_id(),
            wait_config,
            account_data,
            false,
            DeployAccountVersion::V3,
        )
        .await?;

        let deploy_account_hash = deploy_account(
            test_input.random_paymaster_account.provider(),
            test_input.random_paymaster_account.chain_id(),
            wait_config,
            account_data,
            DeployAccountVersion::V3,
        )
        .await?;

        wait_for_sent_transaction(
            deploy_account_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let receipt = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_receipt(deploy_account_hash)
            .await;

        let result = receipt.is_ok();

        assert_result!(result);

        let receipt = match receipt? {
            TxnReceipt::DeployAccount(receipt) => receipt,
            _ => {
                return Err(OpenRpcTestGenError::CallError(
                    CallError::UnexpectedReceiptType,
                ))
            }
        };

        assert_result!(
            receipt.contract_address == account_data.address,
            format!(
                "Expected contract address: {:?}, actual: {:?}",
                account_data.address, receipt.contract_address
            )
        );

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
            common_receipt_properties.transaction_hash == deploy_account_hash,
            format!(
                "Expected transaction hash: {:?}, actual: {:?}",
                deploy_account_hash, common_receipt_properties.transaction_hash
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
            events.len() == 2,
            format!("Expected 2 event, got {}", events.len())
        );

        let first_event = events
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Event not found".to_string()))?;
        assert_result!(
            first_event.from_address == account_data.address,
            format!(
                "Expected event from address to be {:?}, but got {:?}",
                account_data.address, first_event.from_address
            )
        );

        assert_result!(
            first_event.data.is_empty(),
            format!(
                "Expected event data to be empty, but got {}",
                first_event.data.len()
            )
        );

        let first_event_keys_first = *first_event
            .keys
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing first event key".to_string()))?;
        let keccak_owner_added = starknet_keccak("OwnerAdded".as_bytes());
        assert_result!(
            first_event_keys_first == keccak_owner_added,
            format!(
                "Invalid event key, expected {:?}, got {:?}",
                keccak_owner_added, first_event_keys_first
            )
        );

        let first_event_keys_second = *first_event
            .keys
            .get(1)
            .ok_or_else(|| OpenRpcTestGenError::Other("Missing first event key".to_string()))?;
        let account_public_key = account_data.signing_key.verifying_key().scalar();
        assert_result!(
            first_event_keys_second == account_public_key,
            format!(
                "Invalid key (new guid) in event, expected {:?}, got {:?}",
                account_public_key, first_event_keys_second
            )
        );

        let second_event = events
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
            second_event_keys_second == account_data.address,
            format!(
                "Invalid sender address in event keys, expected {}, got {:?}",
                account_data.address, second_event_keys_second
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
