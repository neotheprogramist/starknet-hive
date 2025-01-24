use crate::utils::v7::accounts::account::Account;
use crate::utils::v7::accounts::call::Call;
use crate::utils::v7::accounts::creation::create::{create_account, AccountType};
use crate::utils::v7::accounts::deployment::deploy::{
    deploy_account_v3_from_request, get_deploy_account_request, DeployAccountVersion,
};
use crate::utils::v7::accounts::deployment::structs::{ValidatedWaitParams, WaitForTx};
use crate::utils::v7::endpoints::utils::{get_selector_from_name, wait_for_sent_transaction};
use crate::{assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::{
        accounts::account::ConnectedAccount, endpoints::errors::OpenRpcTestGenError,
        providers::provider::Provider,
    },
    RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{DaMode, DeployAccountTxn, Txn};
use t9n::txn_validation::deploy_account::verify_deploy_account_v3_signature;

const DEPLOY_ACCOUNT_TXN_GAS: u64 = 886;
const DEPLOY_ACCOUNT_TXN_GAS_PRICE: u128 = 15;

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

        let (is_valid_signature, deploy_hash) = verify_deploy_account_v3_signature(
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

        let txn = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_by_hash(deploy_account_result.transaction_hash)
            .await;

        let result = txn.is_ok();
        assert_result!(result);

        let txn = match txn? {
            Txn::DeployAccount(DeployAccountTxn::V3(txn)) => txn,
            _ => {
                return Err(OpenRpcTestGenError::Other(
                    "Expected Deploy Account Txn".to_string(),
                ))
            }
        };

        let expected_class_hash = test_input.account_class_hash;
        assert_result!(
            txn.class_hash == expected_class_hash,
            format!(
                "Expected class hash to be {:?}, but got {:?}",
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
            txn.contract_address_salt == account_data.salt,
            format!(
                "Expected contract address salt to be {:?}, but got {:?}.",
                account_data.salt, txn.contract_address_salt
            )
        );

        let expected_nonce_damode = DaMode::L1;
        assert_result!(
            txn.nonce_data_availability_mode == expected_nonce_damode,
            format!(
                "Expected nonce data availability mode to be {:?}, but got {:?}.",
                expected_nonce_damode, txn.nonce_data_availability_mode
            )
        );

        assert_result!(
            txn.nonce == Felt::ZERO,
            format!(
                "Expected max fee to be {:?}, but got {:?}.",
                Felt::ZERO,
                txn.nonce
            )
        );

        let expected_fee_damode = DaMode::L1;
        assert_result!(
            txn.fee_data_availability_mode == expected_fee_damode,
            format!(
                "Expected fee data availability mode to be {:?}, but got {:?}.",
                expected_fee_damode, txn.fee_data_availability_mode
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

        assert_result!(
            txn.paymaster_data.is_empty(),
            format!(
                "Expected paymaster data to be empty, but it was not. Got: {:?}",
                txn.paymaster_data
            )
        );

        let expected_tip = Felt::ZERO;
        assert_result!(
            txn.tip == expected_tip,
            format!(
                "Expected tip to be {:?}, but got {:?}",
                expected_tip, txn.tip
            )
        );

        let deploy_account_tx_gas_hex =
            Felt::from_dec_str(&DEPLOY_ACCOUNT_TXN_GAS.to_string())?.to_hex_string();
        assert_result!(
            txn.resource_bounds.l1_gas.max_amount == deploy_account_tx_gas_hex,
            format!(
                "Expected l1 gas max amount to be {:?}, but got {:?}",
                deploy_account_tx_gas_hex, txn.resource_bounds.l1_gas.max_amount
            )
        );

        let deploy_account_txn_gas_price_hex =
            Felt::from_dec_str(&DEPLOY_ACCOUNT_TXN_GAS_PRICE.to_string())?.to_hex_string();
        assert_result!(
            txn.resource_bounds.l1_gas.max_price_per_unit == deploy_account_txn_gas_price_hex,
            format!(
                "Expected l1 gas max price per unit
             to be {:?}, but got {:?}",
                deploy_account_txn_gas_price_hex, txn.resource_bounds.l1_gas.max_price_per_unit
            )
        );

        let expected_l2_gas_max_amount = Felt::ZERO.to_hex_string();
        assert_result!(
            txn.resource_bounds.l2_gas.max_amount == expected_l2_gas_max_amount,
            format!(
                "Expected l2 gas max amount to be {:?}, but got {:?}",
                expected_l2_gas_max_amount, txn.resource_bounds.l2_gas.max_amount
            )
        );

        let expected_l2_gas_max_price_per_unit = Felt::ZERO.to_hex_string();
        assert_result!(
            txn.resource_bounds.l2_gas.max_price_per_unit == expected_l2_gas_max_price_per_unit,
            format!(
                "Expected l2 gas max price per unit
             to be {:?}, but got {:?}",
                expected_l2_gas_max_price_per_unit, txn.resource_bounds.l2_gas.max_price_per_unit
            )
        );

        Ok(Self {})
    }
}
