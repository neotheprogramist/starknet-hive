use crate::{
    assert_matches_result,
    utils::{
        outside_execution::{get_current_timestamp, prepare_outside_execution, OutsideExecution},
        v7::{
            accounts::{
                account::{Account, ConnectedAccount},
                call::Call,
                creation::create::{create_account, AccountType},
            },
            endpoints::{
                errors::OpenRpcTestGenError,
                utils::{get_selector_from_name, wait_for_sent_transaction},
            },
            providers::provider::Provider,
        },
    },
    RandomizableAccountsTrait, RunnableTrait,
};

use starknet_types_core::felt::Felt;

use starknet_types_rpc::{BlockId, BlockTag, InvokeTxn, MaybePendingBlockWithTxs, Txn};

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

        let nonce = test_input
            .random_paymaster_account
            .provider()
            .get_nonce(
                BlockId::Tag(BlockTag::Latest),
                test_input.random_paymaster_account.address(),
            )
            .await?;

        let udc_call = Call {
            to: Felt::from_hex_unchecked(
                "0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf",
            ),
            selector: get_selector_from_name("deployContract")?,
            calldata: vec![
                test_input.account_class_hash,
                account_data.salt,
                Felt::ONE,
                Felt::ONE,
                account_data.signing_key.verifying_key().scalar(),
            ],
        };

        let timestamp =
            get_current_timestamp(&test_input.random_paymaster_account.provider()).await?;

        let outside_execution = OutsideExecution {
            caller: test_input.random_paymaster_account.address(),
            execute_before: timestamp + 500,
            execute_after: timestamp - 500,
            nonce: nonce + Felt::ONE,
            calls: vec![udc_call],
        };

        let calldata_to_executable_account_call = prepare_outside_execution(
            &outside_execution,
            test_input
                .random_executable_account
                .random_accounts()?
                .address(),
            test_input.executable_private_key,
            test_input
                .random_paymaster_account
                .provider()
                .chain_id()
                .await?,
        )
        .await?;
        let call_to_executable_account = Call {
            to: test_input
                .random_executable_account
                .random_accounts()?
                .address(),
            selector: get_selector_from_name("execute_from_outside_v2")?,
            calldata: calldata_to_executable_account_call,
        };

        let deploy_hash = test_input
            .random_paymaster_account
            .execute_v3(vec![call_to_executable_account])
            .nonce(
                test_input
                    .random_paymaster_account
                    .provider()
                    .get_nonce(
                        BlockId::Tag(BlockTag::Pending),
                        test_input.random_paymaster_account.address(),
                    )
                    .await?,
            )
            .send()
            .await?
            .transaction_hash;

        wait_for_sent_transaction(
            deploy_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let block_number = test_input
            .random_paymaster_account
            .provider()
            .block_hash_and_number()
            .await?
            .block_number;

        let block_with_txns = test_input
            .random_paymaster_account
            .provider()
            .get_block_with_txs(BlockId::Number(block_number))
            .await?;

        let txn_index: u64 = match block_with_txns {
            MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs
                .transactions
                .iter()
                .position(|tx| tx.transaction_hash == deploy_hash)
                .ok_or_else(|| OpenRpcTestGenError::TransactionNotFound(deploy_hash.to_string()))?
                .try_into()
                .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
            MaybePendingBlockWithTxs::Pending(block_with_txs) => block_with_txs
                .transactions
                .iter()
                .position(|tx| tx.transaction_hash == deploy_hash)
                .ok_or_else(|| OpenRpcTestGenError::TransactionNotFound(deploy_hash.to_string()))?
                .try_into()
                .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
        };

        let txn = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_by_block_id_and_index(BlockId::Number(block_number), txn_index)
            .await?;

        assert_matches_result!(txn, Txn::Invoke(InvokeTxn::V3(_)));

        Ok(Self {})
    }
}
