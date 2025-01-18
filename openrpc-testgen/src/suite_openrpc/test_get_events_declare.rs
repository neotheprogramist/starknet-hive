use std::path::PathBuf;
use std::str::FromStr;

use crate::utils::v7::accounts::account::{starknet_keccak, Account, ConnectedAccount};
use crate::utils::v7::endpoints::declare_contract::get_compiled_contract;
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::provider::{Provider, ProviderError};
use crate::{assert_result, RandomizableAccountsTrait};
use crate::{utils::v7::endpoints::errors::OpenRpcTestGenError, RunnableTrait};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag, EventFilterWithPageRequest, MaybePendingBlockWithTxs};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl13_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl13_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let sender = test_input.random_paymaster_account.random_accounts()?;
        let strk_address =
            Felt::from_hex("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D")?;

        let estimate_fee = sender
            .declare_v3(flattened_sierra_class.clone(), compiled_class_hash)
            .estimate_fee()
            .await?;

        let declaration_result = sender
            .declare_v3(flattened_sierra_class.clone(), compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declaration_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let block_hash_and_number = test_input
            .random_paymaster_account
            .provider()
            .block_hash_and_number()
            .await?;

        let filter = EventFilterWithPageRequest {
            address: None,
            from_block: Some(BlockId::Hash(block_hash_and_number.block_hash)),
            to_block: Some(BlockId::Hash(block_hash_and_number.block_hash)),
            keys: Some(vec![vec![]]),
            chunk_size: 10,
            continuation_token: None,
        };

        let events = test_input
            .random_paymaster_account
            .provider()
            .get_events(filter)
            .await;

        let result = events.is_ok();

        assert_result!(result);

        let events = events?;

        let first_event = events.events.first().ok_or_else(|| {
            OpenRpcTestGenError::Other("First event (declaration) not found".to_string())
        })?;

        assert_result!(
            events.continuation_token.is_none(),
            format!(
                "No continuation token expected. Expected None, got {:?}",
                events.continuation_token
            )
        );

        assert_result!(
            events.events.len() == 1,
            format!(
                "Invalid events count, expected {}, got {}",
                1,
                events.events.len()
            )
        );

        // Check from address
        assert_result!(
            first_event.event.from_address == strk_address,
            format!(
                "Invalid from address in event, expected {}, got {}",
                strk_address, first_event.event.from_address
            )
        );

        // Check data
        let data = &first_event.event.data;
        assert_result!(
            data.first() == Some(&estimate_fee.overall_fee),
            format!(
                "Invalid fee (transfer) amount in event data, expected {}, got {:?}",
                estimate_fee.overall_fee,
                data.first()
            )
        );

        assert_result!(
            data.get(1) == Some(&Felt::ZERO),
            format!(
                "Invalid fee (transfer) amount in event data, expected {}, got {:?}",
                Felt::ZERO,
                data.get(1)
            )
        );

        // Check keys
        let transfer_keccak = starknet_keccak("Transfer".as_bytes());
        let keys = &first_event.event.keys;
        assert_result!(
            keys.first() == Some(&transfer_keccak),
            format!(
                "Invalid keccak transfer in event keys, expected {}, got {:?}",
                transfer_keccak,
                keys.first()
            )
        );

        let sender_address = sender.address();
        assert_result!(
            keys.get(1) == Some(&sender_address),
            format!(
                "Invalid sender address in event keys, expected {}, got {:?}",
                sender_address,
                keys.get(1)
            )
        );

        let maybe_pending_block_with_txs = test_input
            .random_paymaster_account
            .provider()
            .get_block_with_txs(BlockId::Tag(BlockTag::Latest))
            .await?;
        let sequencer_address = match maybe_pending_block_with_txs {
            MaybePendingBlockWithTxs::Block(block_with_txs) => {
                block_with_txs.block_header.sequencer_address
            }
            _ => {
                return Err(OpenRpcTestGenError::ProviderError(
                    ProviderError::UnexpectedPendingBlock,
                ))
            }
        };

        assert_result!(
            keys.get(2) == Some(&sequencer_address),
            format!(
                "Invalid sequencer address in event keys, expected {}, got {:?}",
                sequencer_address,
                keys.get(2)
            )
        );

        // Check block hash and number
        assert_result!(
            first_event.block_hash == Some(block_hash_and_number.block_hash),
            format!(
                "Invalid block hash in event, expected {:?}, got {:?}",
                Some(block_hash_and_number.block_hash),
                first_event.block_hash
            )
        );

        assert_result!(
            first_event.block_number == Some(block_hash_and_number.block_number),
            format!(
                "Invalid block number in event, expected {:?}, got {:?}",
                Some(block_hash_and_number.block_number),
                first_event.block_number
            )
        );

        // Check transaction hash
        assert_result!(
            first_event.transaction_hash == declaration_result.transaction_hash,
            format!(
                "Invalid transaction hash in event, expected {:?}, got {:?}",
                declaration_result.transaction_hash, first_event.transaction_hash
            )
        );

        Ok(Self {})
    }
}
