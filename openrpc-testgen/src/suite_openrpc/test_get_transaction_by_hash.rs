use crate::utils::v7::accounts::account::Account;
use crate::utils::v7::accounts::call::Call;
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::{assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::{
        accounts::{
            account::ConnectedAccount,
            creation::create::{create_account, AccountType},
        },
        endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
        providers::provider::Provider,
        signers::key_pair::SigningKey,
    },
    RunnableTrait,
};
use starknet_types_core::felt::Felt;

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let created_account_data = create_account(
            test_input.random_paymaster_account.provider(),
            AccountType::Oz,
            Option::None,
            Some(test_input.account_class_hash),
        )
        .await?;

        let deploy_account_call = Call {
            to: test_input.udc_address,
            selector: get_selector_from_name("deployContract")?,
            calldata: vec![
                test_input.account_class_hash,
                created_account_data.salt,
                Felt::ZERO,
                Felt::ONE,
                SigningKey::verifying_key(&created_account_data.signing_key).scalar(),
            ],
        };

        let deploy_account_result = test_input
            .random_paymaster_account
            .execute_v3(vec![deploy_account_call])
            .send()
            .await?;

        wait_for_sent_transaction(
            deploy_account_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let txn = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_by_hash(deploy_account_result.transaction_hash)
            .await;

        let result = txn.is_ok();

        assert_result!(result);

        Ok(Self {})
    }
}
