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

        let first_event = events
            .events
            .first()
            .ok_or_else(|| OpenRpcTestGenError::Other("First event not found".to_string()))?;

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

        assert_result!(
            first_event.event.from_address == account_data.address,
            format!(
                "Invalid udc (from) address in event, expected {:?}, got {:?}",
                account_data.address, first_event.event.from_address
            )
        );

        assert_result!(
            first_event.event.data.is_empty(),
            format!(
                "Expected event data to be empty, expected {}, got {}",
                0,
                first_event.event.data.len()
            )
        );

        let keccak_owner_added = starknet_keccak("OwnerAdded".as_bytes());
        assert_result!(
            first_event.event.keys.first() == Some(&keccak_owner_added),
            format!(
                "Invalid event key, expected {:?}, got {:?}",
                keccak_owner_added,
                first_event.event.keys.first()
            )
        );

        let public_key = account_data.signing_key.verifying_key().scalar();
        assert_result!(
            first_event.event.keys.get(1) == Some(&public_key),
            format!(
                "Invalid account key (new guid) in event, expected {:?}, got {:?}",
                public_key,
                first_event.event.keys.get(1)
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
            first_event.transaction_hash == deploy_account_hash,
            format!(
                "Invalid deploy account hash in event, expected {:?}, got {:?}",
                deploy_account_hash, first_event.transaction_hash
            )
        );

        // Second Event
        let second_event = events
            .events
            .get(1)
            .ok_or_else(|| OpenRpcTestGenError::Other("Second event not found".to_string()))?;

        let strk_address =
            Felt::from_hex("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D")?;

        assert_result!(
            second_event.event.from_address == strk_address,
            format!(
                "Invalid from address in event, expected {}, got {}",
                strk_address, second_event.event.from_address
            )
        );

        assert_result!(
            second_event.event.data.first() == Some(&account_data.max_fee),
            format!(
                "Invalid fee amount in event data, expected {}, got {:?}",
                account_data.max_fee,
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

        let keccak_transfer = starknet_keccak("Transfer".as_bytes());
        assert_result!(
            second_event.event.keys.first() == Some(&keccak_transfer),
            format!(
                "Invalid keccak transfer in event keys, expected {}, got {:?}",
                keccak_transfer,
                second_event.event.keys.first()
            )
        );

        assert_result!(
            second_event.event.keys.get(1) == Some(&account_data.address),
            format!(
                "Invalid sender address in event keys, expected {}, got {:?}",
                account_data.address,
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
            second_event.transaction_hash == deploy_account_hash,
            format!(
                "Invalid transaction hash in event, expected {:?}, got {:?}",
                deploy_account_hash, second_event.transaction_hash
            )
        );

        Ok(Self {})
    }
}
