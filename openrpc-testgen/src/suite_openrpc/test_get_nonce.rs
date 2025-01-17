use std::path::PathBuf;
use std::str::FromStr;

use crate::utils::v7::accounts::account::{Account, ConnectedAccount};
use crate::utils::v7::accounts::creation::create::{create_account, AccountType};
use crate::utils::v7::accounts::creation::helpers::get_chain_id;
use crate::utils::v7::accounts::deployment::deploy::{deploy_account, DeployAccountVersion};
use crate::utils::v7::accounts::deployment::structs::{ValidatedWaitParams, WaitForTx};
use crate::utils::v7::accounts::single_owner::{ExecutionEncoding, SingleOwnerAccount};
use crate::utils::v7::endpoints::declare_contract::get_compiled_contract;
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::provider::Provider;
use crate::utils::v7::signers::local_wallet::LocalWallet;
use crate::{assert_result, RandomizableAccountsTrait};
use crate::{
    utils::v7::{
        accounts::call::Call,
        endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
    },
    RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
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

        let initial_account_nonce = test_input
            .random_paymaster_account
            .provider()
            .get_nonce(BlockId::Tag(BlockTag::Latest), account.address)
            .await;

        let result = initial_account_nonce.is_ok();

        assert_result!(result);

        let initial_account_nonce = initial_account_nonce?;
        assert_result!(
            initial_account_nonce == Felt::ONE,
            "New account - expected nonce to be 1"
        );

        let provider = test_input.random_paymaster_account.provider();
        let chain_id = get_chain_id(provider).await?;
        let mut account = SingleOwnerAccount::new(
            &provider,
            LocalWallet::from(account.signing_key),
            account.address,
            chain_id,
            ExecutionEncoding::New,
        );
        account.set_block_id(BlockId::Tag(BlockTag::Pending));

        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl12_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl12_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let declaration_result = account
            .declare_v3(flattened_sierra_class.clone(), compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declaration_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let updated_account_nonce = test_input
            .random_paymaster_account
            .provider()
            .get_nonce(BlockId::Tag(BlockTag::Latest), account.address())
            .await;

        let result = updated_account_nonce.is_ok();

        assert_result!(result);

        let updated_account_nonce = updated_account_nonce?;

        assert_result!(
            updated_account_nonce == Felt::TWO,
            "New account - expected nonce to be 2"
        );

        Ok(Self {})
    }
}
