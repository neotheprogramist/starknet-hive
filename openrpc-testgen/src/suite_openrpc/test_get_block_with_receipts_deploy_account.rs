use crate::{
    assert_result,
    utils::v7::{
        accounts::{
            account::{starknet_keccak, Account, ConnectedAccount},
            call::Call,
            creation::create::{create_account, AccountType},
            deployment::{
                deploy::{
                    deploy_account_v3_from_request, estimate_fee_deploy_account,
                    get_deploy_account_request, DeployAccountVersion,
                },
                structs::{ValidatedWaitParams, WaitForTx},
            },
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
    BlockId, BlockStatus, BlockTag, DaMode, DeployAccountTxn, PriceUnit, TransactionAndReceipt,
    Txn, TxnFinalityStatus, TxnReceipt,
};
use t9n::txn_validation::deploy_account::verify_deploy_account_v3_signature;

const STRK_GAS_PRICE: Felt = Felt::from_hex_unchecked("0xa");
const STRK_BLOB_GAS_PRICE: Felt = Felt::from_hex_unchecked("0x14");
const GAS_PRICE: Felt = Felt::from_hex_unchecked("0x1e");
const BLOB_GAS_PRICE: Felt = Felt::from_hex_unchecked("0x28");
const DEPLOY_ACCOUNT_TXN_GAS: u64 = 886;
const DEPLOY_ACCOUNT_TXN_GAS_PRICE: u128 = 15;
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

        let txn_req = get_deploy_account_request(
            test_input.random_paymaster_account.provider(),
            test_input.random_paymaster_account.chain_id(),
            wait_config,
            account_data,
            DeployAccountVersion::V3,
        )
        .await?;

        let deploy_account_request = match txn_req {
            DeployAccountTxn::V3(txn_req) => txn_req,
            _ => {
                return Err(OpenRpcTestGenError::UnexpectedTxnType(format!(
                    "Unexpected transaction request type: {:?}",
                    txn_req
                )));
            }
        };

        let signature = deploy_account_request.clone().signature;

        let (is_valid_signature, deploy_hash) = verify_deploy_account_v3_signature(
            &deploy_account_request,
            None,
            test_input
                .random_paymaster_account
                .chain_id()
                .to_hex_string()
                .as_str(),
        )?;

        let deploy_account_result = deploy_account_v3_from_request(
            test_input.random_paymaster_account.provider(),
            deploy_account_request,
        )
        .await?;

        wait_for_sent_transaction(
            deploy_account_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        assert_result!(
            deploy_account_result.transaction_hash == deploy_hash,
            format!(
                "Invalid transaction hash, expected {:?}, got {:?}",
                deploy_hash, deploy_account_result.transaction_hash
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
                "Expected block hash to be {:?}, but got {:?}.",
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
                "Expected L1 data gas price in FRI to be {:?}, but got {:?}.",
                block_header.l1_data_gas_price.price_in_fri, STRK_BLOB_GAS_PRICE
            )
        );

        assert_result!(
            block_header.l1_data_gas_price.price_in_wei == BLOB_GAS_PRICE,
            format!(
                "Expected L1 data gas price in WEI to be {:?}, but got {:?}.",
                block_header.l1_data_gas_price.price_in_wei, BLOB_GAS_PRICE
            )
        );

        assert_result!(
            block_header.l1_gas_price.price_in_fri == STRK_GAS_PRICE,
            format!(
                "Expected L1 gas price in FRI to be {:?}, but got {:?}.",
                block_header.l1_gas_price.price_in_fri, STRK_GAS_PRICE
            )
        );

        assert_result!(
            block_header.l1_gas_price.price_in_wei == GAS_PRICE,
            format!(
                "Expected L1 gas price in WEI to be {:?}, but got {:?}.",
                block_header.l1_gas_price.price_in_wei, GAS_PRICE
            )
        );

        let TransactionAndReceipt {
            transaction,
            receipt,
        } = block_with_receipts.transactions.first().ok_or_else(|| {
            OpenRpcTestGenError::Other("Transaction not found in block with receipts".to_string())
        })?;

        let deploy_account_receipt = match receipt {
            TxnReceipt::DeployAccount(deploy_account_receipt) => deploy_account_receipt,
            _ => {
                return Err(OpenRpcTestGenError::UnexpectedTxnType(
                    "Expected Deploy Account Receipt.".to_string(),
                ));
            }
        };

        let deploy_account_tx = match transaction {
            Txn::DeployAccount(deploy_tx) => match deploy_tx {
                DeployAccountTxn::V3(v3_tx) => v3_tx,
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

        // Deploy Account Txn
        let input_class_hash = test_input.account_class_hash;
        assert_result!(
            deploy_account_tx.class_hash == input_class_hash,
            format!(
                "Expected class hash to be {:?}, but got: {:?}.",
                input_class_hash, deploy_account_tx.class_hash
            )
        );

        let constructor_calldata_len = deploy_account_tx.constructor_calldata.len();
        assert_result!(
            constructor_calldata_len == 1,
            format!(
                "Expected constructor calldata length to be 1, but got {}.",
                constructor_calldata_len
            )
        );

        let constructor_calldata =
            *deploy_account_tx
                .constructor_calldata
                .first()
                .ok_or_else(|| {
                    OpenRpcTestGenError::Other("Missing constructor calldata".to_string())
                })?;
        let account_public_key = account_data.signing_key.verifying_key().scalar();
        assert_result!(
            constructor_calldata == account_public_key,
            format!(
                "Expected constructor calldata to be {:?}, but got {:?}.",
                account_public_key, constructor_calldata
            )
        );

        assert_result!(
            deploy_account_tx.contract_address_salt == account_data.salt,
            format!(
                "Expected contract address salt to be {:?}, but got {:?}.",
                account_data.salt, deploy_account_tx.contract_address_salt
            )
        );

        assert_result!(
            deploy_account_tx.nonce_data_availability_mode == DaMode::L1,
            format!(
                "Expected nonce data availability mode to be {:?}, but got {:?}.",
                DaMode::L1,
                deploy_account_tx.nonce_data_availability_mode
            )
        );

        assert_result!(
            deploy_account_tx.nonce == Felt::ZERO,
            format!(
                "Expected max fee to be {:?}, but got {:?}.",
                Felt::ZERO,
                deploy_account_tx.nonce
            )
        );

        assert_result!(
            deploy_account_tx.fee_data_availability_mode == DaMode::L1,
            format!(
                "Expected fee data availability mode to be {:?}, but got {:?}.",
                DaMode::L1,
                deploy_account_tx.fee_data_availability_mode
            )
        );

        assert_result!(
            deploy_account_tx.paymaster_data.is_empty(),
            format!(
                "Expected paymaster data to be empty, but it was not. Got: {:?}",
                deploy_account_tx.paymaster_data
            )
        );

        let expected_tip = Felt::ZERO;
        assert_result!(
            deploy_account_tx.tip == expected_tip,
            format!(
                "Expected tip to be {:?}, but got {:?}",
                expected_tip, deploy_account_tx.tip
            )
        );

        let deploy_account_tx_gas_hex =
            Felt::from_dec_str(&DEPLOY_ACCOUNT_TXN_GAS.to_string())?.to_hex_string();
        assert_result!(
            deploy_account_tx.resource_bounds.l1_gas.max_amount == deploy_account_tx_gas_hex,
            format!(
                "Expected l1 gas max amount to be {:?}, but got {:?}",
                deploy_account_tx_gas_hex, deploy_account_tx.resource_bounds.l1_gas.max_amount
            )
        );

        let deploy_account_txn_gas_price_hex =
            Felt::from_dec_str(&DEPLOY_ACCOUNT_TXN_GAS_PRICE.to_string())?.to_hex_string();
        assert_result!(
            deploy_account_tx.resource_bounds.l1_gas.max_price_per_unit
                == deploy_account_txn_gas_price_hex,
            format!(
                "Expected l1 gas max price per unit
                 to be {:?}, but got {:?}",
                deploy_account_txn_gas_price_hex,
                deploy_account_tx.resource_bounds.l1_gas.max_price_per_unit
            )
        );

        let expected_l2_gas_max_amount = Felt::ZERO.to_hex_string();
        assert_result!(
            deploy_account_tx.resource_bounds.l2_gas.max_amount == expected_l2_gas_max_amount,
            format!(
                "Expected l2 gas max amount to be {:?}, but got {:?}",
                expected_l2_gas_max_amount, deploy_account_tx.resource_bounds.l2_gas.max_amount
            )
        );

        let expected_l2_gas_max_price_per_unit = Felt::ZERO.to_hex_string();
        assert_result!(
            deploy_account_tx.resource_bounds.l2_gas.max_price_per_unit
                == expected_l2_gas_max_price_per_unit,
            format!(
                "Expected l2 gas max price per unit
                 to be {:?}, but got {:?}",
                expected_l2_gas_max_price_per_unit,
                deploy_account_tx.resource_bounds.l2_gas.max_price_per_unit
            )
        );

        assert_result!(
            is_valid_signature,
            "Invalid signature for deploy account request, checked by t9n."
        );

        assert_result!(
            deploy_account_tx.signature == signature,
            format!(
                "Expected signature: {:?}, got {:?}",
                signature, deploy_account_tx.signature
            )
        );

        // Deploy Account receipt
        let actual_fee = deploy_account_receipt
            .common_receipt_properties
            .actual_fee
            .clone();

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

        let events = deploy_account_receipt
            .common_receipt_properties
            .events
            .clone();

        assert_result!(
            events.len() == 2,
            format!("Expected 2 events, but got {:#?}", events.len())
        );

        let first_event = deploy_account_receipt
            .common_receipt_properties
            .events
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Event missing".to_string()))?;

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
        assert_result!(
            first_event_keys_second == account_public_key,
            format!(
                "Invalid key (new guid) in event, expected {:?}, got {:?}",
                account_public_key, first_event_keys_second
            )
        );

        let second_event = deploy_account_receipt
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
                "Invalid fee amount in event data, expected {:?}, got {:?}",
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
                "Invalid fee amount in event data, expected {:?}, got {:?}",
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
                "Invalid keccak transfer in event keys, expected {:?}, got {:?}",
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
                "Invalid sender address in event keys, expected {:?}, got {:?}",
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
                "Invalid sequencer address in event keys, expected {:?}, got {:?}",
                SEQUENCER_ADDRESS, second_event_keys_third
            )
        );

        let finality_status = deploy_account_receipt
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
            deploy_account_receipt
                .common_receipt_properties
                .messages_sent
                .is_empty(),
            "Expected no messages sent"
        );

        assert_result!(
            deploy_account_receipt
                .common_receipt_properties
                .transaction_hash
                == deploy_account_result.transaction_hash,
            format!(
                "Invalid transaction hash, expected {:?}, got {:?}",
                deploy_account_result.transaction_hash,
                deploy_account_receipt
                    .common_receipt_properties
                    .transaction_hash
            )
        );

        let execution_status = match deploy_account_receipt
            .common_receipt_properties
            .anon
            .clone()
        {
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
