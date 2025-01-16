use std::path::PathBuf;
use std::str::FromStr;

use crate::utils::v7::accounts::account::{starknet_keccak, Account, ConnectedAccount};
use crate::utils::v7::endpoints::declare_contract::get_compiled_contract;
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::provider::Provider;
use crate::{assert_result, RandomizableAccountsTrait};
use crate::{utils::v7::endpoints::errors::OpenRpcTestGenError, RunnableTrait};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, EventFilterWithPageRequest};

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
            .await?;

        println!("events: {events:#?}");

        assert_result!(
            events.events.len() == 1,
            format!(
                "Invalid events count, expected {}, got {}",
                1,
                events.events.len()
            )
        );

        assert_result!(
            events.events[0].event.from_address == strk_address,
            format!(
                "Invalid from address in event, expected {}, got {}",
                strk_address, events.events[0].event.from_address
            )
        );

        assert_result!(
            events.events[0].event.data[0] == estimate_fee.overall_fee,
            format!(
                "Invalid fee (transfer) amount in event data, expected {}, got {}",
                estimate_fee.overall_fee, events.events[0].event.data[0]
            )
        );

        assert_result!(
            events.events[0].event.data[1] == Felt::ZERO,
            format!(
                "Invalid fee (transfer) amount in event data, expected {}, got {}",
                Felt::ZERO,
                events.events[0].event.data[1]
            )
        );

        let keccak_transfer = starknet_keccak("Transfer".as_bytes());
        assert_result!(
            events.events[0].event.keys[0] == keccak_transfer,
            format!(
                "Invalid keccak transfer in event keys, expected {}, got {}",
                keccak_transfer, events.events[0].event.keys[0]
            )
        );

        let sender_address = sender.address();
        assert_result!(
            events.events[0].event.keys[1] == sender_address,
            format!(
                "Invalid sender address in event keys, expected {}, got {}",
                sender_address, events.events[0].event.keys[1]
            )
        );

        let sequencer_address = Felt::from_hex("0x123")?;
        assert_result!(
            events.events[0].event.keys[2] == sequencer_address,
            format!(
                "Invalid sequencer address in event keys, expected {}, got {}",
                sequencer_address, events.events[0].event.keys[2]
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
            events.events[0].transaction_hash == declaration_result.transaction_hash,
            format!(
                "Invalid transaction hash in event, expected {:?}, got {:?}",
                declaration_result.transaction_hash, events.events[0].transaction_hash
            )
        );

        Ok(Self {})
    }
}
