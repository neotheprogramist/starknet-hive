use std::path::PathBuf;
use std::str::FromStr;

use crate::utils::v7::accounts::account::{starknet_keccak, Account, ConnectedAccount};
use crate::utils::v7::contract::factory::ContractFactory;
use crate::utils::v7::endpoints::declare_contract::get_compiled_contract;
use crate::utils::v7::endpoints::errors::CallError;
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::provider::Provider;
use crate::{assert_result, RandomizableAccountsTrait};
use crate::{utils::v7::endpoints::errors::OpenRpcTestGenError, RunnableTrait};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, EventFilterWithPageRequest, TxnReceipt};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl14_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl14_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let declaration_result = test_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class.clone(), compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declaration_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let sender = test_input.random_paymaster_account.random_accounts()?;
        let strk_address =
            Felt::from_hex("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D")?;

        let factory = ContractFactory::new(declaration_result.class_hash, sender.clone());
        let mut salt_buffer = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut salt_buffer[1..]);

        let unique = true;
        let constructor_calldata = vec![];
        let salt = Felt::from_bytes_be(&salt_buffer);

        let estimate_fee = factory
            .deploy_v3(constructor_calldata.clone(), salt, unique)
            .estimate_fee()
            .await?;

        let deploy_result = factory
            .deploy_v3(constructor_calldata.clone(), salt, unique)
            .send()
            .await?;

        wait_for_sent_transaction(
            deploy_result.transaction_hash,
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

        let deployment_receipt = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_receipt(deploy_result.transaction_hash)
            .await?;

        let deployed_contract_address = match &deployment_receipt {
            TxnReceipt::Deploy(receipt) => receipt.contract_address,
            TxnReceipt::Invoke(receipt) => {
                if let Some(contract_address) = receipt
                    .common_receipt_properties
                    .events
                    .first()
                    .and_then(|event| event.data.first())
                {
                    *contract_address
                } else {
                    return Err(OpenRpcTestGenError::CallError(
                        CallError::UnexpectedReceiptType,
                    ));
                }
            }
            _ => {
                return Err(OpenRpcTestGenError::CallError(
                    CallError::UnexpectedReceiptType,
                ));
            }
        };

        assert_result!(
            events.events.len() == 2,
            format!(
                "Invalid events count, expected {}, got {}",
                2,
                events.events.len()
            )
        );

        let udc_address = test_input.udc_address;
        assert_result!(
            events.events[0].event.from_address == udc_address,
            format!(
                "Invalid udc (from) address in event, expected {:?}, got {:?}",
                udc_address, events.events[0].event.from_address
            )
        );

        assert_result!(
            events.events[0].event.data[0] == deployed_contract_address,
            format!(
                "Invalid deployed contract address in event, expected {:?}, got {:?}",
                deployed_contract_address, events.events[0].event.data[0]
            )
        );

        let sender_address = sender.address();
        assert_result!(
            events.events[0].event.data[1] == sender_address,
            format!(
                "Invalid sender address in event, expected {:?}, got {:?}",
                sender_address, events.events[0].event.data[1]
            )
        );

        assert_result!(
            events.events[0].event.data[2] == Felt::ONE,
            format!(
                "Invalid unique in event, expected {:?}, got {:?}",
                Felt::ONE,
                events.events[0].event.data[2]
            )
        );

        assert_result!(
            events.events[0].event.data[3] == declaration_result.class_hash,
            format!(
                "Invalid class hash in event, expected {:?}, got {:?}",
                declaration_result.class_hash, events.events[0].event.data[3]
            )
        );

        let contructor_calldata_len = Felt::from_dec_str(&constructor_calldata.len().to_string())?;
        assert_result!(
            events.events[0].event.data[4] == contructor_calldata_len,
            format!(
                "Invalid constructor calldata length in event, expected {:?}, got {:?}",
                contructor_calldata_len, events.events[0].event.data[4]
            )
        );

        assert_result!(
            events.events[0].event.data[5] == salt,
            format!(
                "Invalid salt in event, expected {:?}, got {:?}",
                salt, events.events[0].event.data[5]
            )
        );

        let keccak_contract_deployed = starknet_keccak("ContractDeployed".as_bytes());
        assert_result!(
            events.events[0].event.keys[0] == keccak_contract_deployed,
            format!(
                "Invalid keccak transfer in event keys, expected {:?}, got {:?}",
                keccak_contract_deployed, events.events[0].event.keys[0]
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
            events.events[0].transaction_hash == deploy_result.transaction_hash,
            format!(
                "Invalid transaction hash in event, expected {:?}, got {:?}",
                deploy_result.transaction_hash, events.events[0].transaction_hash
            )
        );

        // Second event
        assert_result!(
            events.events[1].event.from_address == strk_address,
            format!(
                "Invalid from address in event, expected {}, got {}",
                strk_address, events.events[0].event.from_address
            )
        );

        assert_result!(
            events.events[1].event.data[0] == estimate_fee.overall_fee,
            format!(
                "Invalid fee amount in event data, expected {}, got {}",
                estimate_fee.overall_fee, events.events[1].event.data[0]
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
                keccak_transfer, events.events[0].event.keys[0]
            )
        );

        assert_result!(
            events.events[1].event.keys[1] == sender_address,
            format!(
                "Invalid sender address in event keys, expected {}, got {}",
                sender_address, events.events[1].event.keys[1]
            )
        );

        let sequencer_address = Felt::from_hex("0x123")?;
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
            events.events[1].transaction_hash == deploy_result.transaction_hash,
            format!(
                "Invalid transaction hash in event, expected {:?}, got {:?}",
                deploy_result.transaction_hash, events.events[1].transaction_hash
            )
        );

        Ok(Self {})
    }
}
