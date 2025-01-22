use starknet_types_core::felt::Felt;

use crate::{
    assert_result,
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

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let initial_block_number = test_input
            .random_paymaster_account
            .provider()
            .block_number()
            .await?;

        let account = create_account(
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
                calldata: vec![account.address, transfer_amount, Felt::ZERO],
            }])
            .send()
            .await?;

        wait_for_sent_transaction(
            transfer_execution.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let block_number_after_first_tx = test_input
            .random_paymaster_account
            .provider()
            .block_number()
            .await?;

        assert_result!(
            block_number_after_first_tx == initial_block_number + 1,
            format!(
                "Exptected block number to be {:?}, but got {:?}.",
                initial_block_number + 1,
                block_number_after_first_tx
            )
        );

        let wait_config = WaitForTx {
            wait: true,
            wait_params: ValidatedWaitParams::default(),
        };

        let deploy_account_hash = deploy_account(
            test_input.random_paymaster_account.provider(),
            test_input.random_paymaster_account.chain_id(),
            wait_config,
            account,
            DeployAccountVersion::V3,
        )
        .await?;

        wait_for_sent_transaction(
            deploy_account_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let block_number_after_second_tx = test_input
            .random_paymaster_account
            .provider()
            .block_number()
            .await?;

        assert_result!(
            block_number_after_second_tx == block_number_after_first_tx + 1,
            format!(
                "Exptected block number to be {:?}, but got {:?}.",
                block_number_after_first_tx + 1,
                block_number_after_second_tx
            )
        );

        Ok(Self {})
    }
}
