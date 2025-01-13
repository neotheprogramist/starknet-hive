use std::path::PathBuf;
use std::str::FromStr;

use crate::utils::v7::accounts::account::{Account, ConnectedAccount};
use crate::utils::v7::contract::factory::ContractFactory;
use crate::utils::v7::endpoints::declare_contract::get_compiled_contract;
use crate::utils::v7::endpoints::errors::CallError;
use crate::utils::v7::endpoints::utils::wait_for_sent_transaction;
use crate::utils::v7::providers::provider::Provider;
use crate::{assert_result, RandomizableAccountsTrait};
use crate::{utils::v7::endpoints::errors::OpenRpcTestGenError, RunnableTrait};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag, TxnReceipt};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteDeploy;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl11_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl11_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let declaration_result = test_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class.clone(), compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declaration_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let factory = ContractFactory::new(
            declaration_result.class_hash,
            test_input.random_paymaster_account.random_accounts()?,
        );

        let mut salt_buffer = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut salt_buffer[1..]);

        let deployment_result = factory
            .deploy_v3(vec![], Felt::from_bytes_be(&salt_buffer), true)
            .send()
            .await?;

        wait_for_sent_transaction(
            deployment_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let deployment_receipt = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_receipt(deployment_result.transaction_hash)
            .await?;

        let deployed_contract_address = match &deployment_receipt {
            TxnReceipt::Deploy(receipt) => receipt.contract_address,
            TxnReceipt::Invoke(receipt) => {
                if let Some(contract_address) = receipt
                    .common_receipt_properties
                    .events
                    .first()
                    .and_then(|event| event.data.first())
                {
                    *contract_address
                } else {
                    return Err(OpenRpcTestGenError::CallError(
                        CallError::UnexpectedReceiptType,
                    ));
                }
            }
            _ => {
                return Err(OpenRpcTestGenError::CallError(
                    CallError::UnexpectedReceiptType,
                ));
            }
        };

        let contract_class_hash = test_input
            .random_paymaster_account
            .provider()
            .get_class_hash_at(BlockId::Tag(BlockTag::Latest), deployed_contract_address)
            .await;

        let result = contract_class_hash.is_ok();

        assert_result!(result);

        let contract_class_hash = contract_class_hash?;

        assert_result!(
            contract_class_hash == declaration_result.class_hash,
            format!(
                "Class hash mismatch: expected {}, got {}",
                declaration_result.class_hash, contract_class_hash
            )
        );

        Ok(Self {})
    }
}
