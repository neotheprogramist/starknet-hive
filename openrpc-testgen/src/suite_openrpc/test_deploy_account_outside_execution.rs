use crate::{
    assert_matches_result,
    utils::v7::{
        accounts::{
            account::{Account, ConnectedAccount},
            call::Call,
            creation::create::{create_account, AccountType},
        },
        endpoints::{
            endpoints_functions::OutsideExecution,
            errors::OpenRpcTestGenError,
            utils::{get_selector_from_name, wait_for_sent_transaction},
        },
        providers::provider::Provider,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use cainome_cairo_serde::CairoSerde;
use starknet::core::crypto::ecdsa_sign;
use starknet_types_core::{
    felt::Felt,
    hash::{Poseidon, StarkHash},
};
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

        let outside_execution = OutsideExecution {
            caller: test_input.random_paymaster_account.address(),
            nonce: Felt::ZERO,
            calls: vec![udc_call],
        };

        let outside_execution_cairo_serialized =
            &OutsideExecution::cairo_serialize(&outside_execution);

        let hash = Poseidon::hash_array(outside_execution_cairo_serialized);

        let starknet::core::crypto::ExtendedSignature { r, s, v: _ } =
            ecdsa_sign(&test_input.paymaster_private_key, &hash).unwrap();

        let mut calldata_to_executable_account_call = outside_execution_cairo_serialized.clone();
        calldata_to_executable_account_call.push(Felt::from_dec_str("2")?);
        calldata_to_executable_account_call.push(r);
        calldata_to_executable_account_call.push(s);

        let call_to_executable_account = Call {
            to: test_input
                .random_executable_account
                .random_accounts()?
                .address(),
            selector: get_selector_from_name("execute_from_outside")?,
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
