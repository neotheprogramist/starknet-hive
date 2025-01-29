use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, MaybePendingBlockWithTxs};

use crate::utils::starknet_hive::StarknetHive;
use crate::{
    assert_result,
    utils::v7::{
        accounts::{
            account::{Account, ConnectedAccount},
            call::Call,
        },
        endpoints::{
            errors::OpenRpcTestGenError,
            utils::{get_selector_from_name, wait_for_sent_transaction},
        },
        providers::provider::{Provider, ProviderError},
    },
    RandomizableAccountsTrait, RunnableTrait,
};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let hive = test_input.hive.clone();
        let initial_block_hash_and_number = hive.provider().block_hash_and_number().await;

        let result = initial_block_hash_and_number.is_ok();

        assert_result!(result);

        let initial_block_hash_and_number = initial_block_hash_and_number?;

        let initial_block_number = hive.provider().block_number().await?;

        assert_result!(
            initial_block_hash_and_number.block_number == initial_block_number,
            format!(
                "Mismatch initial block number: {} != {}",
                initial_block_hash_and_number.block_number, initial_block_number
            )
        );

        let block_with_txs = hive
            .provider()
            .get_block_with_txs(BlockId::Number(initial_block_number))
            .await?;

        let initial_block_hash = match block_with_txs {
            MaybePendingBlockWithTxs::Block(block) => block.block_header.block_hash,
            _ => {
                return Err(OpenRpcTestGenError::ProviderError(
                    ProviderError::UnexpectedPendingBlock,
                ))
            }
        };

        assert_result!(
            initial_block_hash_and_number.block_hash == initial_block_hash,
            format!(
                "Mismatch initial block hash: {} != {}",
                initial_block_hash_and_number.block_hash, initial_block_hash
            )
        );

        let transfer_amount = Felt::from_hex("0xfffffffffffffff")?;

        let transfer_execution = hive
            .execute_v3(vec![Call {
                to: Felt::from_hex(
                    "0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D",
                )?,
                selector: get_selector_from_name("transfer")?,
                calldata: vec![
                    Felt::from_hex(
                        "0xdeadF5A0beefCC1Adead1CDEbeefFB20dead5CD6beefB072dead8F42beef38D",
                    )?,
                    transfer_amount,
                    Felt::ZERO,
                ],
            }])
            .send()
            .await?;

        wait_for_sent_transaction(transfer_execution.transaction_hash, &hive.account).await?;

        let initial_block_hash_and_number = hive.provider().block_hash_and_number().await;

        let result = initial_block_hash_and_number.is_ok();

        assert_result!(result);

        let initial_block_hash_and_number = initial_block_hash_and_number?;

        let initial_block_number = hive.provider().block_number().await?;

        assert_result!(
            initial_block_hash_and_number.block_number == initial_block_number,
            format!(
                "Mismatch initial block number: {} != {}",
                initial_block_hash_and_number.block_number, initial_block_number
            )
        );

        let block_with_txs = hive
            .provider()
            .get_block_with_txs(BlockId::Number(initial_block_number))
            .await?;

        let initial_block_hash = match block_with_txs {
            MaybePendingBlockWithTxs::Block(block) => block.block_header.block_hash,
            _ => {
                return Err(OpenRpcTestGenError::ProviderError(
                    ProviderError::UnexpectedPendingBlock,
                ))
            }
        };

        assert_result!(
            initial_block_hash_and_number.block_hash == initial_block_hash,
            format!(
                "Mismatch initial block hash: {} != {}",
                initial_block_hash_and_number.block_hash, initial_block_hash
            )
        );

        println!("block hash and number success");

        Ok(Self {})
    }
}
