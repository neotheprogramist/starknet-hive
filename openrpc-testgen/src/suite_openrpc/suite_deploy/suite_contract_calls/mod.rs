use rand::{rngs::StdRng, RngCore, SeedableRng};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::TxnReceipt;

use super::RandomSingleOwnerAccount;
use crate::{
    utils::v7::{
        accounts::account::ConnectedAccount,
        contract::factory::ContractFactory,
        endpoints::{
            errors::{CallError, OpenRpcTestGenError},
            utils::wait_for_sent_transaction,
        },
        providers::provider::Provider,
    },
    RandomizableAccountsTrait, SetupableTrait,
};

pub mod test_call_contract;
pub mod test_call_error_block_not_found;
pub mod test_call_error_contract_error;
pub mod test_call_error_contract_not_found;
pub mod test_estimate_message_fee;
pub mod test_get_storage_at;
pub mod test_get_storage_at_map;
pub mod test_get_txn_by_block_id_and_index_invoke_v1;
pub mod test_get_txn_by_block_id_and_index_invoke_v3;
pub mod test_get_txn_receipt_invoke;
pub mod test_get_txn_status;
pub mod test_invoke_contract_v1;
pub mod test_invoke_contract_v3;
pub mod test_invoke_v3_trace;
pub mod test_simulate_invoke_v3_skip_fee;
pub mod test_simulate_invoke_v3_skip_validate_skip_fee;
pub mod test_trace_block_txn_invoke;

pub struct TestSuiteContractCalls {
    pub random_paymaster_account: RandomSingleOwnerAccount,
    pub random_executable_account: RandomSingleOwnerAccount,
    pub deployment_receipt: TxnReceipt<Felt>,
    pub deployed_contract_address: Felt,
    pub account_class_hash: Felt,
}

impl SetupableTrait for TestSuiteContractCalls {
    type Input = super::TestSuiteDeploy;

    async fn setup(setup_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let factory = ContractFactory::new(
            setup_input.declaration_result.class_hash,
            setup_input.random_paymaster_account.random_accounts()?,
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
            &setup_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let deployment_receipt = setup_input
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

        Ok(Self {
            random_paymaster_account: setup_input.random_paymaster_account.clone(),
            random_executable_account: setup_input.random_executable_account.clone(),
            deployment_receipt,
            deployed_contract_address,
            account_class_hash: setup_input.account_class_hash,
        })
    }
}

#[cfg(not(feature = "rust-analyzer"))]
include!(concat!(
    env!("OUT_DIR"),
    "/generated_tests_suite_openrpc_suite_deploy_suite_contract_calls.rs"
));
