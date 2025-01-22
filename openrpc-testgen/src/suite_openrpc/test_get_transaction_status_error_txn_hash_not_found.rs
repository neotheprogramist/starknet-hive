use crate::utils::v7::accounts::account::{Account, ConnectedAccount};
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::jsonrpc::StarknetError;
use crate::utils::v7::providers::provider::{Provider, ProviderError};
use crate::{assert_matches_result, assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::{
        accounts::call::Call,
        endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
    },
    RunnableTrait,
};
use starknet_types_core::felt::Felt;

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let strk_address =
            Felt::from_hex("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D")?;
        let receiptent_address =
            Felt::from_hex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefd3ad")?;
        let transfer_amount = Felt::from_hex("0xfffffffffffffff")?;
        let sender = test_input.random_paymaster_account.random_accounts()?;

        let transfer_execution = sender
            .execute_v3(vec![Call {
                to: strk_address,
                selector: get_selector_from_name("transfer")?,
                calldata: vec![receiptent_address, transfer_amount, Felt::ZERO],
            }])
            .send()
            .await?;

        wait_for_sent_transaction(
            transfer_execution.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let txn_status = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_status(transfer_execution.transaction_hash + Felt::THREE)
            .await;

        let result = txn_status.is_err();
        assert_result!(result);

        assert_matches_result!(
            txn_status.unwrap_err(),
            ProviderError::StarknetError(StarknetError::TransactionHashNotFound)
        );

        Ok(Self {})
    }
}
