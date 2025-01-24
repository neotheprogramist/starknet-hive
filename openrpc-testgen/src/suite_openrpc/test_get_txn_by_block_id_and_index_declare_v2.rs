use crate::{
    assert_result,
    utils::v7::{
        accounts::account::{Account, ConnectedAccount},
        endpoints::{
            declare_contract::get_compiled_contract, errors::OpenRpcTestGenError,
            utils::wait_for_sent_transaction,
        },
        providers::provider::Provider,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, DeclareTxn, MaybePendingBlockWithTxs, Txn};
use std::{path::PathBuf, str::FromStr, sync::Arc};
use t9n::txn_validation::declare::verify_declare_v2_signature;

const EXPECTED_MAX_FEE: Felt = Felt::from_hex_unchecked("0xfbee6");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl4_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl4_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let sender = test_input.random_paymaster_account.random_accounts()?;
        let sender_nonce = sender.get_nonce().await?;
        let sender_address = sender.address();

        let prepared_declaration = sender
            .declare_v2(Arc::new(flattened_sierra_class), compiled_class_hash)
            .prepare()
            .await?;

        let declaration_request = prepared_declaration
            .get_declare_request(false, false)
            .await?;

        let (valid_signature, declare_hash) = verify_declare_v2_signature(
            &declaration_request,
            None,
            sender.provider().chain_id().await?.to_hex_string().as_str(),
        )?;

        let signature = declaration_request.clone().signature;

        let declaration_result = prepared_declaration
            .send_from_request(declaration_request)
            .await?;

        wait_for_sent_transaction(
            declaration_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        assert_result!(
            declaration_result.transaction_hash == declare_hash,
            format!(
                "Invalid transaction hash, expected {:?}, got {:?}",
                declare_hash, declaration_result.transaction_hash
            )
        );

        let block_hash = test_input
            .random_paymaster_account
            .provider()
            .block_hash_and_number()
            .await?
            .block_hash;

        // Looking for txn index in the block
        let block_with_txns = test_input
            .random_paymaster_account
            .provider()
            .get_block_with_txs(BlockId::Hash(block_hash))
            .await?;
        let txn_index: u64 = match block_with_txns {
            MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs
                .transactions
                .iter()
                .position(|tx| tx.transaction_hash == declaration_result.transaction_hash)
                .ok_or_else(|| {
                    OpenRpcTestGenError::TransactionNotFound(
                        declaration_result.transaction_hash.to_string(),
                    )
                })?
                .try_into()
                .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
            MaybePendingBlockWithTxs::Pending(block_with_txs) => block_with_txs
                .transactions
                .iter()
                .position(|tx| tx.transaction_hash == declaration_result.transaction_hash)
                .ok_or_else(|| {
                    OpenRpcTestGenError::TransactionNotFound(
                        declaration_result.transaction_hash.to_string(),
                    )
                })?
                .try_into()
                .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
        };

        let txn = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_by_block_id_and_index(BlockId::Hash(block_hash), txn_index)
            .await;

        let result = txn.is_ok();
        assert_result!(result);

        let txn = match txn? {
            Txn::Declare(DeclareTxn::V2(txn)) => txn,
            _ => {
                return Err(OpenRpcTestGenError::UnexpectedTxnType(
                    "Unexpected txn type ".to_string(),
                ));
            }
        };

        assert_result!(
            txn.class_hash == declaration_result.class_hash,
            format!(
                "Expected txn class hash to be {:?} but got {:?}",
                declaration_result.class_hash, txn.class_hash
            )
        );

        assert_result!(
            txn.compiled_class_hash == compiled_class_hash,
            format!(
                "Expected txn compiled class hash to be {:?} but got {:?}",
                compiled_class_hash, txn.compiled_class_hash
            )
        );

        assert_result!(
            txn.max_fee == EXPECTED_MAX_FEE,
            format!(
                "Expected txn max fee to be {:?} but got {:?}",
                EXPECTED_MAX_FEE, txn.max_fee
            )
        );

        assert_result!(
            txn.nonce == sender_nonce,
            format!(
                "Expected txn nonce to be {:?} but got {:?}",
                sender_nonce, txn.nonce
            )
        );

        assert_result!(
            txn.sender_address == sender_address,
            format!(
                "Expected txn sender address to be {:?} but got {:?}",
                sender_address, txn.sender_address
            )
        );

        assert_result!(
            valid_signature,
            format!("Invalid signature, checked by t9n.",)
        );

        assert_result!(
            txn.signature == signature,
            format!(
                "Expected signature: {:?}, got {:?}",
                signature, txn.signature
            )
        );

        Ok(Self {})
    }
}
