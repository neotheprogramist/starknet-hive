use crate::{
    utils::v7::{
        accounts::{
            account::{Account, ConnectedAccount},
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
        providers::provider::Provider,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use colored::Colorize;
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, DeployAccountTxn, MaybePendingBlockWithTxs, Txn};
use tracing::{error, info};

// TODO discuss this test case
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
                .position(|tx| tx.transaction_hash == deploy_account_hash)
                .ok_or_else(|| {
                    OpenRpcTestGenError::TransactionNotFound(deploy_account_hash.to_string())
                })?
                .try_into()
                .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
            MaybePendingBlockWithTxs::Pending(block_with_txs) => block_with_txs
                .transactions
                .iter()
                .position(|tx| tx.transaction_hash == deploy_account_hash)
                .ok_or_else(|| {
                    OpenRpcTestGenError::TransactionNotFound(deploy_account_hash.to_string())
                })?
                .try_into()
                .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
        };

        let txn = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_by_block_id_and_index(BlockId::Number(block_number), txn_index)
            .await?;

        match txn {
            Txn::DeployAccount(DeployAccountTxn::V3(_)) => {
                info!(
                    "{} {}",
                    "\n✓ Rpc get_transaction_by_block_id_and_index_deploy_account_v3 COMPATIBLE"
                        .green(),
                    "✓".green()
                );
            }
            _ => {
                let error_message = format!("Unexpected transaction response type: {:?}", txn);
                error!(
                    "{} {} {}",
                    "✗ Rpc get_transaction_by_block_id_and_index_deploy_account_v3 INCOMPATIBLE:"
                        .red(),
                    error_message,
                    "✗".red()
                );
                return Err(OpenRpcTestGenError::UnexpectedTxnType(error_message));
            }
        }

        Ok(Self {})
    }
}
