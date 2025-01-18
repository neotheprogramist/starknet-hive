use crate::utils::v7::accounts::account::{starknet_keccak, Account, ConnectedAccount};
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::provider::{Provider, ProviderError};
use crate::{assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::{
        accounts::call::Call,
        endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
    },
    RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag, EventFilterWithPageRequest, MaybePendingBlockWithTxs};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let strk_address =
            Felt::from_hex("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D")?;
        let receiptent_address =
            Felt::from_hex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead")?;
        let transfer_amount = Felt::from_hex("0xfffffffffffffff")?;
        let sender = test_input.random_paymaster_account.random_accounts()?;

        let estimate_fee = sender
            .execute_v3(vec![Call {
                to: strk_address,
                selector: get_selector_from_name("transfer")?,
                calldata: vec![receiptent_address, transfer_amount, Felt::ZERO],
            }])
            .estimate_fee()
            .await?;

        let transfer_execution = sender
            .execute_v3(vec![Call {
                to: strk_address,
                selector: get_selector_from_name("transfer")?,
                calldata: vec![receiptent_address, transfer_amount, Felt::ZERO],
            }])
            .send()
            .await?;

        wait_for_sent_transaction(
            transfer_execution.transaction_hash,
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

        assert_result!(
            events.continuation_token.is_none(),
            format!(
                "No continuation token expected. Expected None, got {:?}",
                events.continuation_token
            )
        );

        assert_result!(
            events.events.len() == 2,
            format!(
                "Invalid events count, expected {}, got {}",
                2,
                events.events.len()
            )
        );

        let first_event = events
            .events
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("Failed to get first event".to_string()))?;

        assert_result!(
            first_event.event.from_address == strk_address,
            format!(
                "Invalid from address in event, expected {}, got {}",
                strk_address, first_event.event.from_address
            )
        );

        assert_result!(
            first_event.event.data.first() == Some(&transfer_amount),
            format!(
                "Invalid transfer amount in event data, expected {}, got {:?}",
                transfer_amount,
                first_event.event.data.first()
            )
        );

        assert_result!(
            first_event.event.data.get(1) == Some(&Felt::ZERO),
            format!(
                "Invalid transfer amount in event data, expected {}, got {:?}",
                Felt::ZERO,
                first_event.event.data.get(1)
            )
        );

        let keccak_transfer = starknet_keccak("Transfer".as_bytes());
        assert_result!(
            first_event.event.keys.first() == Some(&keccak_transfer),
            format!(
                "Invalid keccak transfer in event keys, expected {}, got {:?}",
                keccak_transfer,
                first_event.event.keys.first()
            )
        );

        let sender_address = sender.address();
        assert_result!(
            first_event.event.keys.get(1) == Some(&sender_address),
            format!(
                "Invalid sender address in event keys, expected {}, got {:?}",
                sender_address,
                first_event.event.keys.get(1)
            )
        );

        assert_result!(
            first_event.event.keys.get(2) == Some(&receiptent_address),
            format!(
                "Invalid recipient address in event keys, expected {}, got {:?}",
                receiptent_address,
                first_event.event.keys.get(2)
            )
        );

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

        assert_result!(
            first_event.transaction_hash == transfer_execution.transaction_hash,
            format!(
                "Invalid transaction hash in event, expected {:?}, got {:?}",
                transfer_execution.transaction_hash, first_event.transaction_hash
            )
        );

        // Second event
        let second_event = events
            .events
            .get(1)
            .ok_or_else(|| OpenRpcTestGenError::Other("Failed to get second event".to_string()))?;

        assert_result!(
            second_event.event.from_address == strk_address,
            format!(
                "Invalid from address in event, expected {}, got {}",
                strk_address, second_event.event.from_address
            )
        );

        assert_result!(
            second_event.event.data.first() == Some(&estimate_fee.overall_fee),
            format!(
                "Invalid fee amount in event data, expected {}, got {:?}",
                estimate_fee.overall_fee,
                second_event.event.data.first()
            )
        );

        assert_result!(
            second_event.event.data.get(1) == Some(&Felt::ZERO),
            format!(
                "Invalid fee amount in event data, expected {}, got {:?}",
                Felt::ZERO,
                second_event.event.data.get(1)
            )
        );

        assert_result!(
            second_event.event.keys.first() == Some(&keccak_transfer),
            format!(
                "Invalid keccak transfer in event keys, expected {}, got {:?}",
                keccak_transfer,
                second_event.event.keys.first()
            )
        );

        assert_result!(
            second_event.event.keys.get(1) == Some(&sender_address),
            format!(
                "Invalid sender address in event keys, expected {}, got {:?}",
                sender_address,
                second_event.event.keys.get(1)
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
            second_event.event.keys.get(2) == Some(&sequencer_address),
            format!(
                "Invalid sequencer address in event keys, expected {}, got {:?}",
                sequencer_address,
                second_event.event.keys.get(2)
            )
        );

        assert_result!(
            second_event.block_hash == Some(block_hash_and_number.block_hash),
            format!(
                "Invalid block hash in event, expected {:?}, got {:?}",
                Some(block_hash_and_number.block_hash),
                second_event.block_hash
            )
        );

        assert_result!(
            second_event.block_number == Some(block_hash_and_number.block_number),
            format!(
                "Invalid block number in event, expected {:?}, got {:?}",
                Some(block_hash_and_number.block_number),
                second_event.block_number
            )
        );

        assert_result!(
            second_event.transaction_hash == transfer_execution.transaction_hash,
            format!(
                "Invalid transaction hash in event, expected {:?}, got {:?}",
                transfer_execution.transaction_hash, second_event.transaction_hash
            )
        );

        Ok(Self {})
    }
}
