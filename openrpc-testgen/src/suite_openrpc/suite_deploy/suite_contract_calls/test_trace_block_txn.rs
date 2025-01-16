use crate::utils::v7::accounts::account::{Account, ConnectedAccount};
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::provider::Provider;
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
    BlockId, BlockTag, InvokeTransactionTrace, TraceBlockTransactionsResult, TransactionTrace,
};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteContractCalls;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let amount_to_increase = Felt::from_hex_unchecked("0x123");
        let increase_balance_call = Call {
            to: test_input.deployed_contract_address,
            selector: get_selector_from_name("increase_balance")?,
            calldata: vec![amount_to_increase],
        };

        let invoke_result = test_input
            .random_paymaster_account
            .execute_v3(vec![increase_balance_call])
            .send()
            .await?;

        wait_for_sent_transaction(
            invoke_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let trace_block_result = test_input
            .random_paymaster_account
            .provider()
            .trace_block_transactions(BlockId::Tag(BlockTag::Latest))
            .await;

        let result = trace_block_result.is_ok();

        assert_result!(result);

        let trace = trace_block_result?;
        assert_matches_result!(
            trace[0],
            TraceBlockTransactionsResult {
                trace_root: Some(TransactionTrace::Invoke(InvokeTransactionTrace { .. })),
                transaction_hash: Some(_),
            }
        );

        Ok(Self {})
    }
}
