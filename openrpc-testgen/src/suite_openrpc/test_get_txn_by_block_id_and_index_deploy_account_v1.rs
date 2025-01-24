use crate::{
    assert_result,
    utils::v7::{
        accounts::{
            account::{Account, ConnectedAccount},
            call::Call,
            creation::create::{create_account, AccountType},
            deployment::{
                deploy::{
                    deploy_account_v1_from_request, get_deploy_account_request,
                    DeployAccountVersion,
                },
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
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, DeployAccountTxn, MaybePendingBlockWithTxs, Txn};
use t9n::txn_validation::deploy_account::verify_deploy_account_v1_signature;

const EXPECTED_MAX_FEE: Felt = Felt::from_hex_unchecked("0x336f");
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

        let transfer_amount = Felt::from_hex("0xffffffffffff")?;

        let transfer_execution = test_input
            .random_paymaster_account
            .execute_v3(vec![Call {
                to: Felt::from_hex(
                    "0x49D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7",
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

        let txn_req = get_deploy_account_request(
            test_input.random_paymaster_account.provider(),
            test_input.random_paymaster_account.chain_id(),
            wait_config,
            account_data,
            DeployAccountVersion::V1,
        )
        .await?;

        let deploy_account_request = match txn_req {
            DeployAccountTxn::V1(txn_req) => txn_req,
            _ => {
                return Err(OpenRpcTestGenError::UnexpectedTxnType(format!(
                    "Unexpected transaction request type: {:?}",
                    txn_req
                )));
            }
        };

        let signature = deploy_account_request.clone().signature;

        let (is_valid_signature, deploy_hash) = verify_deploy_account_v1_signature(
            &deploy_account_request,
            None,
            test_input
                .random_paymaster_account
                .chain_id()
                .to_hex_string()
                .as_str(),
        )?;

        let deploy_account_result = deploy_account_v1_from_request(
            test_input.random_paymaster_account.provider(),
            deploy_account_request,
        )
        .await?;

        wait_for_sent_transaction(
            deploy_account_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        assert_result!(
            deploy_account_result.transaction_hash == deploy_hash,
            format!(
                "Invalid transaction hash, expected {:?}, got {:?}",
                deploy_hash, deploy_account_result.transaction_hash
            )
        );

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
                .position(|tx| tx.transaction_hash == deploy_account_result.transaction_hash)
                .ok_or_else(|| {
                    OpenRpcTestGenError::TransactionNotFound(
                        deploy_account_result.transaction_hash.to_string(),
                    )
                })?
                .try_into()
                .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
            MaybePendingBlockWithTxs::Pending(block_with_txs) => block_with_txs
                .transactions
                .iter()
                .position(|tx| tx.transaction_hash == deploy_account_result.transaction_hash)
                .ok_or_else(|| {
                    OpenRpcTestGenError::TransactionNotFound(
                        deploy_account_result.transaction_hash.to_string(),
                    )
                })?
                .try_into()
                .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
        };

        let txn = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_by_block_id_and_index(BlockId::Number(block_number), txn_index)
            .await;

        let result = txn.is_ok();
        assert_result!(result);

        let txn = match txn? {
            Txn::DeployAccount(DeployAccountTxn::V1(txn)) => txn,
            _ => {
                return Err(OpenRpcTestGenError::UnexpectedTxnType(
                    "Unexpected txn type ".to_string(),
                ));
            }
        };

        let expected_class_hash = test_input.account_class_hash;
        assert_result!(
            txn.class_hash == expected_class_hash,
            format!(
                "Expected class hash {:?} but got {:?}",
                expected_class_hash, txn.class_hash
            )
        );

        let constructor_calldata_len = txn.constructor_calldata.len();
        assert_result!(
            constructor_calldata_len == 1,
            format!(
                "Expected constructor calldata length to be 1, but got {}.",
                constructor_calldata_len
            )
        );

        let constructor_calldata = *txn.constructor_calldata.first().ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing constructor calldata".to_string())
        })?;
        let account_public_key = account_data.signing_key.verifying_key().scalar();
        assert_result!(
            constructor_calldata == account_public_key,
            format!(
                "Expected constructor calldata to be {:?}, but got {:?}.",
                account_public_key, constructor_calldata
            )
        );

        assert_result!(
            txn.max_fee == EXPECTED_MAX_FEE,
            format!(
                "Expected max fee to be {:?}, but got {:?}.",
                EXPECTED_MAX_FEE, txn.max_fee
            )
        );

        let expected_initial_nonce = Felt::ZERO;
        assert_result!(
            txn.nonce == expected_initial_nonce,
            format!(
                "Expected nonce to be {:?}, but got {:?}.",
                expected_initial_nonce, txn.nonce
            )
        );

        assert_result!(
            is_valid_signature,
            "Invalid signature for deploy account request, checked by t9n."
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
