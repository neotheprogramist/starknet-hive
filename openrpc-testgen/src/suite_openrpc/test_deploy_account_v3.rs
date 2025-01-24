use crate::{
    assert_result,
    utils::v7::{
        accounts::{
            account::{Account, ConnectedAccount},
            call::Call,
            creation::create::{create_account, AccountType},
            deployment::{
                deploy::{
                    deploy_account_v3_from_request, get_deploy_account_request,
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
use starknet_types_rpc::{BlockId, DaMode, DeployAccountTxn, MaybePendingBlockWithTxs, Txn};
use t9n::txn_validation::deploy_account::verify_deploy_account_v3_signature;
const DEPLOY_ACCOUNT_TXN_GAS: Felt = Felt::from_hex_unchecked("0x376");
const DEPLOY_ACCOUNT_TXN_GAS_PRICE: Felt = Felt::from_hex_unchecked("0xf");
const STRK: Felt =
    Felt::from_hex_unchecked("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D");
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
                to: STRK,
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
            DeployAccountVersion::V3,
        )
        .await?;

        let deploy_account_request = match txn_req {
            DeployAccountTxn::V3(txn_req) => txn_req,
            _ => {
                return Err(OpenRpcTestGenError::UnexpectedTxnType(format!(
                    "Unexpected transaction request type: {:?}",
                    txn_req
                )));
            }
        };

        let signature = deploy_account_request.clone().signature;

        let (valid_signature, deploy_hash) = verify_deploy_account_v3_signature(
            &deploy_account_request,
            None,
            test_input
                .random_paymaster_account
                .chain_id()
                .to_hex_string()
                .as_str(),
        )?;

        let deploy_account_result = deploy_account_v3_from_request(
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
            .await?;

        let deploy_account_txn = match txn {
            Txn::DeployAccount(DeployAccountTxn::V3(txn)) => txn,
            _ => {
                return Err(OpenRpcTestGenError::UnexpectedTxnType(format!(
                    "Unexpected transaction response type: {:?}",
                    txn
                )));
            }
        };

        let expected_class_hash = test_input.account_class_hash;
        assert_result!(
            deploy_account_txn.class_hash == expected_class_hash,
            format!(
                "Expected class hash to be {:?}, but got {:?}",
                expected_class_hash, deploy_account_txn.class_hash
            )
        );

        assert_result!(
            deploy_account_txn.constructor_calldata.len() == 1,
            format!(
                "Expected constructor calldata length to be 1, but got {:?}",
                deploy_account_txn.constructor_calldata.len()
            )
        );

        let constructor_calldata =
            *deploy_account_txn
                .constructor_calldata
                .first()
                .ok_or_else(|| {
                    OpenRpcTestGenError::Other("Constructor calldata is empty".to_string())
                })?;

        let expected_account_public_key = account_data.signing_key.verifying_key().scalar();
        assert_result!(
            constructor_calldata == expected_account_public_key,
            format!(
                "Expected constructor calldata to be {:?}, but got {:?}",
                expected_account_public_key, constructor_calldata
            )
        );

        assert_result!(
            valid_signature,
            "Invalid signature for deploy account request, checked by t9n."
        );

        assert_result!(
            deploy_account_txn.signature == signature,
            format!(
                "Expected signature: {:?}, got {:?}",
                signature, deploy_account_txn.signature
            )
        );

        let expected_salt = account_data.salt;
        assert_result!(
            deploy_account_txn.contract_address_salt == expected_salt,
            format!(
                "Expected salt to be {:?}, but got {:?}",
                expected_salt, deploy_account_txn.contract_address_salt
            )
        );

        let expected_fee_damode = DaMode::L1;
        assert_result!(
            deploy_account_txn.fee_data_availability_mode == expected_fee_damode,
            format!(
                "Expected fee data availability mode to be {:?}, but got {:?}",
                expected_fee_damode, deploy_account_txn.fee_data_availability_mode
            )
        );

        let expected_initial_account_nonce = Felt::ZERO;
        assert_result!(
            deploy_account_txn.nonce == expected_initial_account_nonce,
            format!(
                "Expected nonce to be {:?}, but got {:?}",
                expected_initial_account_nonce, deploy_account_txn.nonce
            )
        );

        let expected_nonce_damode = DaMode::L1;
        assert_result!(
            deploy_account_txn.nonce_data_availability_mode == expected_nonce_damode,
            format!(
                "Expected nonce data availability mode to be {:?}, but got {:?}",
                expected_nonce_damode, deploy_account_txn.nonce_data_availability_mode
            )
        );

        assert_result!(
            deploy_account_txn.paymaster_data.is_empty(),
            format!(
                "Expected paymaster data to be empty, but got {:?}",
                deploy_account_txn.paymaster_data
            )
        );

        let l1_gas_max_amount =
            Felt::from_hex(&deploy_account_txn.resource_bounds.l1_gas.max_amount)?;
        assert_result!(
            l1_gas_max_amount == DEPLOY_ACCOUNT_TXN_GAS,
            format!(
                "Expected L1 gas to be {:?}, but got {:?}",
                DEPLOY_ACCOUNT_TXN_GAS, deploy_account_txn.resource_bounds.l1_gas
            )
        );
        let l1_gas_max_price_per_unit =
            Felt::from_hex(&deploy_account_txn.resource_bounds.l1_gas.max_price_per_unit)?;

        assert_result!(
            l1_gas_max_price_per_unit == DEPLOY_ACCOUNT_TXN_GAS_PRICE,
            format!(
                "Expected L1 gas price to be {:?}, but got {:?}",
                DEPLOY_ACCOUNT_TXN_GAS_PRICE, deploy_account_txn.resource_bounds.l1_gas
            )
        );

        let l2_gas_max_amount =
            Felt::from_hex(&deploy_account_txn.resource_bounds.l2_gas.max_amount)?;
        assert_result!(
            l2_gas_max_amount == Felt::ZERO,
            format!(
                "Expected L2 gas to be {:?}, but got {:?}",
                Felt::ZERO,
                deploy_account_txn.resource_bounds.l2_gas
            )
        );
        let l2_gas_max_price_per_unit =
            Felt::from_hex(&deploy_account_txn.resource_bounds.l2_gas.max_price_per_unit)?;

        assert_result!(
            l2_gas_max_price_per_unit == Felt::ZERO,
            format!(
                "Expected L2 gas price to be {:?}, but got {:?}",
                Felt::ZERO,
                deploy_account_txn.resource_bounds.l2_gas
            )
        );

        let expected_tip = Felt::ZERO;
        assert_result!(
            deploy_account_txn.tip == expected_tip,
            format!(
                "Expected tip to be {:?}, but got {:?}",
                expected_tip, deploy_account_txn.tip
            )
        );

        Ok(Self {})
    }
}
