use std::{path::PathBuf, str::FromStr};

use crate::{
    assert_result,
    utils::v7::{
        accounts::account::{Account, ConnectedAccount},
        endpoints::{
            declare_contract::get_compiled_contract, errors::OpenRpcTestGenError,
            utils::wait_for_sent_transaction,
        },
        providers::provider::Provider,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{
    BlockId, BlockStatus, BlockTag, DaMode, DeclareTxn, PriceUnit, TransactionAndReceipt, Txn,
    TxnReceipt,
};
use t9n::txn_validation::declare::verify_declare_v3_signature;
const STRK_GAS_PRICE: Felt = Felt::from_hex_unchecked("0xa");
const STRK_BLOB_GAS_PRICE: Felt = Felt::from_hex_unchecked("0x14");
const GAS_PRICE: Felt = Felt::from_hex_unchecked("0x1e");
const BLOB_GAS_PRICE: Felt = Felt::from_hex_unchecked("0x28");
const DECLARE_TXN_GAS: u64 = 48000;
const DECLARE_TXN_GAS_PRICE: u128 = 17;
#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl3_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl3_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let sender = test_input.random_paymaster_account.random_accounts()?;
        let sender_nonce = sender.get_nonce().await?;
        let chain_id = sender.provider().chain_id().await?;

        let estimate_fee = sender
            .declare_v3(flattened_sierra_class.clone(), compiled_class_hash)
            .estimate_fee()
            .await?;

        let prepared_declaration_v3 = sender
            .declare_v3(flattened_sierra_class, compiled_class_hash)
            .gas(DECLARE_TXN_GAS)
            .gas_price(DECLARE_TXN_GAS_PRICE)
            .prepare_without_send()
            .await?;

        let declare_v3_request = prepared_declaration_v3
            .get_declare_request(false, false)
            .await?;

        let is_valid_signature_and_hash = verify_declare_v3_signature(
            &declare_v3_request,
            None,
            chain_id.to_hex_string().as_str(),
        )?;

        println!("t9n output {:?}", is_valid_signature_and_hash);

        let class_and_tx_hash = prepared_declaration_v3
            .send_from_request(declare_v3_request)
            .await?; // or use prepared_declaration_v3.send().await()

        wait_for_sent_transaction(
            class_and_tx_hash.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let block_hash_and_number = test_input
            .random_paymaster_account
            .provider()
            .block_hash_and_number()
            .await?;

        let block_with_receipts: Result<
            starknet_types_rpc::BlockWithReceipts<Felt>,
            crate::utils::v7::providers::provider::ProviderError,
        > = test_input
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
                "Mismatch expected: {:?}, but got: {:?}",
                BlockStatus::AcceptedOnL2,
                block_with_receipts.status
            )
        );

        let block_header = block_with_receipts.block_header;
        assert_result!(
            block_header.block_hash == block_hash_and_number.block_hash,
            format!(
                "Mismatch block hash: {} != {}",
                block_header.block_hash, block_hash_and_number.block_hash
            )
        );

        assert_result!(
            block_header.block_number == block_hash_and_number.block_number,
            format!(
                "Mismatch block number: {} != {}",
                block_header.block_number, block_hash_and_number.block_number
            )
        );

        assert_result!(
            block_header.l1_data_gas_price.price_in_fri == STRK_BLOB_GAS_PRICE,
            format!(
                "Mismatch l1 data gas price: {} != {}",
                block_header.l1_data_gas_price.price_in_fri, STRK_BLOB_GAS_PRICE
            )
        );

        assert_result!(
            block_header.l1_data_gas_price.price_in_wei == BLOB_GAS_PRICE,
            format!(
                "Mismatch gas price: {} != {}",
                block_header.l1_data_gas_price.price_in_wei, BLOB_GAS_PRICE
            )
        );

        assert_result!(
            block_header.l1_gas_price.price_in_fri == STRK_GAS_PRICE,
            format!(
                "Mismatch l1 gas price: {} != {}",
                block_header.l1_gas_price.price_in_fri, STRK_GAS_PRICE
            )
        );

        assert_result!(
            block_header.l1_gas_price.price_in_wei == GAS_PRICE,
            format!(
                "Mismatch gas price: {} != {}",
                block_header.l1_gas_price.price_in_wei, GAS_PRICE
            )
        );

        let (declare_tx, declare_receipt) =
            match block_with_receipts.transactions.first().ok_or_else(|| {
                OpenRpcTestGenError::Other(
                    "Transaction not found in block with receipts".to_string(),
                )
            })? {
                TransactionAndReceipt {
                    transaction,
                    receipt,
                } => {
                    let declare_tx = match transaction {
                        Txn::Declare(declare_tx) => match declare_tx {
                            DeclareTxn::V3(v3_tx) => {
                                println!("{:?}", estimate_fee);

                                println!("Transaction is V3: {:#?}", v3_tx);
                                v3_tx
                            }
                            _ => {
                                return Err(OpenRpcTestGenError::UnexpectedTxnType(
                                    "Expected Declare V3 Transaction.".to_string(),
                                ));
                            }
                        },
                        _ => {
                            return Err(OpenRpcTestGenError::UnexpectedTxnType(
                                "Expected Declare Transaction.".to_string(),
                            ));
                        }
                    };

                    let declare_receipt = match receipt {
                        TxnReceipt::Declare(declare_receipt) => {
                            println!("declare_receipt: {:#?}", declare_receipt);
                            declare_receipt
                        }
                        _ => {
                            return Err(OpenRpcTestGenError::UnexpectedTxnType(
                                "Expected Declare Transaction Receipt.".to_string(),
                            ));
                        }
                    };

                    (declare_tx, declare_receipt)
                }
            };

        // Declare Txn
        assert_result!(
            declare_tx.account_deployment_data.is_empty(),
            "Expected account deployment data to be empty"
        );

        assert_result!(
            declare_tx.class_hash == class_and_tx_hash.class_hash,
            format!(
                "Expected class hash to be {:?}, got {:?}",
                class_and_tx_hash.class_hash, declare_tx.class_hash
            )
        );

        assert_result!(
            declare_tx.compiled_class_hash == compiled_class_hash,
            format!(
                "Expected compiled class hash to be {:?}, got {:?}",
                compiled_class_hash, declare_tx.compiled_class_hash
            )
        );

        assert_result!(
            declare_tx.fee_data_availability_mode == DaMode::L1,
            format!(
                "Expected fee data availability_mode to be {:?}, got {:?}",
                DaMode::L1,
                declare_tx.fee_data_availability_mode
            )
        );

        assert_result!(
            declare_tx.nonce == sender_nonce,
            format!(
                "Expected nonce to be {:?}, got {:?}",
                sender_nonce, declare_tx.nonce
            )
        );

        assert_result!(
            declare_tx.nonce_data_availability_mode == DaMode::L1,
            format!(
                "Expected nonce data avability mode to be {:?}, got {:?}",
                DaMode::L1,
                declare_tx.nonce_data_availability_mode
            )
        );

        assert_result!(
            declare_tx.paymaster_data.is_empty(),
            "Expected paymaster data to be empty"
        );

        let sender_address = sender.address();
        assert_result!(
            declare_tx.sender_address == sender_address,
            format!(
                "Expected sender address to be {:?}, got {:?}",
                sender_address, declare_tx.sender_address
            )
        );

        let expected_tip = Felt::ZERO.to_hex_string();
        assert_result!(
            declare_tx.tip == expected_tip,
            format!(
                "Expected tip to be {:?}, got {:?}",
                expected_tip, declare_tx.tip
            )
        );
        let declare_txn_gas_hex = Felt::from_dec_str(&DECLARE_TXN_GAS.to_string())?.to_hex_string();
        assert_result!(
            declare_tx.resource_bounds.l1_gas.max_amount == declare_txn_gas_hex,
            format!(
                "Expected l1 gas max amount to be {:?}, got {:?}",
                declare_txn_gas_hex, declare_tx.resource_bounds.l1_gas.max_amount
            )
        );

        let declare_txn_gas_price_hex =
            Felt::from_dec_str(&DECLARE_TXN_GAS_PRICE.to_string())?.to_hex_string();
        assert_result!(
            declare_tx.resource_bounds.l1_gas.max_price_per_unit == declare_txn_gas_price_hex,
            format!(
                "Expected l1 gas max price per unit
                 to be {:?}, got {:?}",
                declare_txn_gas_price_hex, declare_tx.resource_bounds.l1_gas.max_price_per_unit
            )
        );

        let expected_l2_gas_max_amount = Felt::ZERO.to_hex_string();
        assert_result!(
            declare_tx.resource_bounds.l2_gas.max_amount == expected_l2_gas_max_amount,
            format!(
                "Expected l2 gas max amount to be {:?}, got {:?}",
                expected_l2_gas_max_amount, declare_tx.resource_bounds.l2_gas.max_amount
            )
        );

        let expected_l2_gas_max_price_per_unit = Felt::ZERO.to_hex_string();
        assert_result!(
            declare_tx.resource_bounds.l2_gas.max_price_per_unit
                == expected_l2_gas_max_price_per_unit,
            format!(
                "Expected l2 gas max price per unit
                 to be {:?}, got {:?}",
                expected_l2_gas_max_price_per_unit,
                declare_tx.resource_bounds.l2_gas.max_price_per_unit
            )
        );

        // Declare receipt
        let actual_fee = declare_receipt.common_receipt_properties.actual_fee.clone();

        assert_result!(
            actual_fee.amount == estimate_fee.overall_fee,
            format!(
                "Expected overall fee to be {:?}, got {:?}",
                estimate_fee.overall_fee, actual_fee.unit
            )
        );

        assert_result!(
            actual_fee.unit == PriceUnit::Fri,
            format!(
                "Expected price unit to be {:?}, got {:?}",
                PriceUnit::Fri,
                actual_fee.unit
            )
        );

        let event = declare_receipt
            .common_receipt_properties
            .events
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Event missing".to_string()))?;

        Ok(Self {})
    }
}
