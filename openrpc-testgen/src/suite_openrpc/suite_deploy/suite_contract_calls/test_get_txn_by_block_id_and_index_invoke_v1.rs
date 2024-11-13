use crate::utils::v7::accounts::account::Account;
use crate::{
    utils::v7::{
        accounts::{account::ConnectedAccount, call::Call},
        endpoints::{
            errors::RpcError,
            utils::{get_selector_from_name, wait_for_sent_transaction},
        },
        providers::provider::Provider,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use colored::Colorize;
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, InvokeTxn, MaybePendingBlockWithTxs, Txn};
use tracing::{error, info};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteContractCalls;

    async fn run(test_input: &Self::Input) -> Result<Self, RpcError> {
        let increase_balance_call = Call {
            to: test_input.deployed_contract_address,
            selector: get_selector_from_name("increase_balance")?,
            calldata: vec![Felt::from_hex("0x50")?],
        };

        let invoke_result = test_input
            .random_paymaster_account
            .execute_v1(vec![increase_balance_call])
            .send()
            .await?;

        wait_for_sent_transaction(
            invoke_result.transaction_hash,
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
                .position(|tx| tx.transaction_hash == invoke_result.transaction_hash)
                .ok_or_else(|| {
                    RpcError::TransactionNotFound(invoke_result.transaction_hash.to_string())
                })?
                .try_into()
                .map_err(|_| RpcError::TransactionIndexOverflow)?,
            MaybePendingBlockWithTxs::Pending(block_with_txs) => block_with_txs
                .transactions
                .iter()
                .position(|tx| tx.transaction_hash == invoke_result.transaction_hash)
                .ok_or_else(|| {
                    RpcError::TransactionNotFound(invoke_result.transaction_hash.to_string())
                })?
                .try_into()
                .map_err(|_| RpcError::TransactionIndexOverflow)?,
        };

        let txn = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_by_block_id_and_index(BlockId::Number(block_number), txn_index)
            .await?;

        match txn {
            Txn::Invoke(InvokeTxn::V1(_)) => {
                info!(
                    "{} {}",
                    "\n✓ Rpc test_get_txn_by_block_id_and_index_invoke_v1 COMPATIBLE".green(),
                    "✓".green()
                );
            }
            _ => {
                let error_message = format!("Unexpected transaction response type: {:?}", txn);
                error!(
                    "{} {} {}",
                    "✗ Rpc test_get_txn_by_block_id_and_index_invoke_v1 INCOMPATIBLE:".red(),
                    error_message,
                    "✗".red()
                );
                return Err(RpcError::UnexpectedTxnType(error_message));
            }
        }

        Ok(Self {})
    }
}
