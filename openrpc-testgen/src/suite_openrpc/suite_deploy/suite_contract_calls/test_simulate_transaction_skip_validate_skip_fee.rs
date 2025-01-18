use crate::utils::v7::accounts::account::{Account, ConnectedAccount};
use crate::utils::v7::accounts::creation::helpers::get_chain_id;
use crate::utils::v7::accounts::single_owner::{ExecutionEncoding, SingleOwnerAccount};
use crate::utils::v7::signers::key_pair::SigningKey;
use crate::utils::v7::signers::local_wallet::LocalWallet;
use crate::{assert_matches_result, assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::{
        accounts::call::Call,
        endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
    },
    RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{
    FeeEstimate, InvokeTransactionTrace, SimulateTransactionsResult, TransactionTrace,
};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteContractCalls;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let account = test_input.random_paymaster_account.random_accounts()?;

        let provider = account.provider().clone();

        let chain_id = get_chain_id(&provider).await?;

        let account_invalid = SingleOwnerAccount::new(
            account.provider().clone(),
            LocalWallet::from(SigningKey::from_random()),
            account.address(),
            chain_id,
            ExecutionEncoding::New,
        );
        let amount_to_increase = Felt::from_hex_unchecked("0x12345");
        let increase_balance_call = Call {
            to: test_input.deployed_contract_address,
            selector: get_selector_from_name("increase_balance")?,
            calldata: vec![amount_to_increase],
        };

        let invoke_result = account_invalid
            .execute_v3(vec![increase_balance_call])
            .simulate(true, true)
            .await;

        let result = invoke_result.is_ok();

        assert_result!(result);

        let simulate_result = invoke_result?;
        assert_matches_result!(
            simulate_result,
            SimulateTransactionsResult {
                fee_estimation: Some(FeeEstimate { .. }),
                transaction_trace: Some(TransactionTrace::Invoke(InvokeTransactionTrace { .. }))
            }
        );
        Ok(Self {})
    }
}
