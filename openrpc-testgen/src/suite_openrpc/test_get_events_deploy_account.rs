use crate::{
    assert_result,
    utils::v7::{
        accounts::{
            account::{starknet_keccak, Account, ConnectedAccount},
            call::Call,
            creation::create::{create_account, AccountType},
            deployment::{
                deploy::{deploy_account, DeployAccountVersion},
                structs::{ValidatedWaitParams, WaitForTx},
            },
        },
        endpoints::{
            errors::OpenRpcTestGenError,
            utils::{get_selector_from_name, wait_for_sent_transaction},
        },
        providers::provider::{Provider, ProviderError},
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag, EventFilterWithPageRequest, MaybePendingBlockWithTxs};

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
            events.events.len() == 2,
            format!(
                "Invalid events count, expected {}, got {}",
                2,
                events.events.len()
            )
        );

        assert_result!(
            events.events[0].event.from_address == account_data.address,
            format!(
                "Invalid udc (from) address in event, expected {:?}, got {:?}",
                account_data.address, events.events[0].event.from_address
            )
        );

        assert_result!(
            events.events[0].event.data.is_empty(),
            format!(
                "Expected event data to be empty, expected {}, got {}",
                0,
                events.events[0].event.data.len()
            )
        );

        let keccak_owner_added = starknet_keccak("OwnerAdded".as_bytes());
        assert_result!(
            events.events[0].event.keys[0] == keccak_owner_added,
            format!(
                "Invalid event key, expected {:?}, got {:?}",
                keccak_owner_added, events.events[0].event.keys[0]
            )
        );

        let public_key = account_data.signing_key.verifying_key().scalar();
        assert_result!(
            events.events[0].event.keys[1] == public_key,
            format!(
                "Invalid account key (new guid) in event, expected {:?}, got {:?}",
                public_key, events.events[0].event.keys[1]
            )
        );

        assert_result!(
            events.events[0].block_hash == Some(block_hash_and_number.block_hash),
            format!(
                "Invalid block hash in event, expected {:?}, got {:?}",
                Some(block_hash_and_number.block_hash),
                events.events[0].block_hash
            )
        );

        assert_result!(
            events.events[0].block_number == Some(block_hash_and_number.block_number),
            format!(
                "Invalid block number in event, expected {:?}, got {:?}",
                Some(block_hash_and_number.block_number),
                events.events[0].block_number
            )
        );

        assert_result!(
            events.events[0].transaction_hash == deploy_account_hash,
            format!(
                "Invalid deploy account hash in event, expected {:?}, got {:?}",
                deploy_account_hash, events.events[0].transaction_hash
            )
        );

        // Second Event
        let strk_address =
            Felt::from_hex("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D")?;

        assert_result!(
            events.events[1].event.from_address == strk_address,
            format!(
                "Invalid from address in event, expected {}, got {}",
                strk_address, events.events[1].event.from_address
            )
        );

        assert_result!(
            events.events[1].event.data[0] == account_data.max_fee,
            format!(
                "Invalid fee amount in event data, expected {}, got {}",
                account_data.max_fee, events.events[1].event.data[0]
            )
        );

        assert_result!(
            events.events[1].event.data[1] == Felt::ZERO,
            format!(
                "Invalid fee amount in event data, expected {}, got {}",
                Felt::ZERO,
                events.events[1].event.data[1]
            )
        );

        let keccak_transfer = starknet_keccak("Transfer".as_bytes());
        assert_result!(
            events.events[1].event.keys[0] == keccak_transfer,
            format!(
                "Invalid keccak transfer in event keys, expected {}, got {}",
                keccak_transfer, events.events[1].event.keys[0]
            )
        );

        assert_result!(
            events.events[1].event.keys[1] == account_data.address,
            format!(
                "Invalid sender address in event keys, expected {}, got {}",
                account_data.address, events.events[1].event.keys[1]
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
            events.events[1].event.keys[2] == sequencer_address,
            format!(
                "Invalid sequencer address in event keys, expected {}, got {}",
                sequencer_address, events.events[1].event.keys[2]
            )
        );

        assert_result!(
            events.events[1].block_hash == Some(block_hash_and_number.block_hash),
            format!(
                "Invalid block hash in event, expected {:?}, got {:?}",
                Some(block_hash_and_number.block_hash),
                events.events[1].block_hash
            )
        );

        assert_result!(
            events.events[1].block_number == Some(block_hash_and_number.block_number),
            format!(
                "Invalid block number in event, expected {:?}, got {:?}",
                Some(block_hash_and_number.block_number),
                events.events[1].block_number
            )
        );

        assert_result!(
            events.events[1].transaction_hash == deploy_account_hash,
            format!(
                "Invalid transaction hash in event, expected {:?}, got {:?}",
                deploy_account_hash, events.events[1].transaction_hash
            )
        );

        Ok(Self {})
    }
}
