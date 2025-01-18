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
use starknet_types_rpc::{BlockId, BlockStatus, BlockTag};

const STRK_GAS_PRICE: Felt = Felt::from_hex_unchecked("0xa");
const STRK_BLOB_GAS_PRICE: Felt = Felt::from_hex_unchecked("0x14");
const GAS_PRICE: Felt = Felt::from_hex_unchecked("0x1e");
const BLOB_GAS_PRICE: Felt = Felt::from_hex_unchecked("0x28");

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

        let declaration_hash = test_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class, compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declaration_hash.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let block_hash_and_number = test_input
            .random_paymaster_account
            .provider()
            .block_hash_and_number()
            .await?;

        let block_with_receipts = test_input
            .random_paymaster_account
            .provider()
            .get_block_with_receipts(BlockId::Tag(BlockTag::Latest))
            .await;

        let result = block_with_receipts.is_ok();
        assert_result!(result);

        let block_with_receipts = block_with_receipts?;
        println!("block_with_receipts: {:#?}", block_with_receipts);

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

        // let transaction = *block_with_receipts.transactions.first().ok_or_else(|| {
        //     OpenRpcTestGenError::Other("Transaction not found in block with receipts".to_string())
        // })?;

        Ok(Self {})
    }
}
