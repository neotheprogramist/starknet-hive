use std::{path::PathBuf, str::FromStr};

use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag};
use url::Url;

use crate::{
    utils::{
        random_single_owner_account::RandomSingleOwnerAccount,
        v7::{
            accounts::{
                account::{Account, AccountError},
                call::Call,
                creation::{
                    create::{create_account, AccountType},
                    helpers::get_chain_id,
                },
                single_owner::{ExecutionEncoding, SingleOwnerAccount},
            },
            endpoints::{
                declare_contract::{
                    extract_class_hash_from_error, get_compiled_contract,
                    parse_class_hash_from_error, RunnerError,
                },
                errors::OpenRpcTestGenError,
                utils::{get_selector_from_name, wait_for_sent_transaction},
            },
            providers::{
                jsonrpc::{HttpTransport, JsonRpcClient},
                provider::ProviderError,
            },
            signers::{key_pair::SigningKey, local_wallet::LocalWallet},
        },
    },
    SetupableTrait,
};

pub mod suite_deploy;
pub mod test_block_hash_and_number;
pub mod test_declare_txn_v2;
pub mod test_declare_txn_v3;
pub mod test_declare_v3_trace;
pub mod test_deploy_account_outside_execution;
pub mod test_deploy_account_trace;
pub mod test_deploy_account_v1;
pub mod test_deploy_account_v3;
pub mod test_erc20_transfer_outside_execution;
pub mod test_estimate_fee_fri;
pub mod test_estimate_fee_wei;
pub mod test_get_block_number;
pub mod test_get_block_txn_count;
pub mod test_get_block_with_receipts_declare;
pub mod test_get_block_with_receipts_deploy;
pub mod test_get_block_with_receipts_deploy_account;
pub mod test_get_block_with_receipts_invoke;
pub mod test_get_block_with_tx_hashes;
pub mod test_get_block_with_txs;
pub mod test_get_chain_id;
pub mod test_get_class;
pub mod test_get_events_declare;
pub mod test_get_events_deploy;
pub mod test_get_events_deploy_account;
pub mod test_get_events_transfer;
pub mod test_get_nonce;
pub mod test_get_state_update;
pub mod test_get_storage_class_proof;
pub mod test_get_storage_contract_proof;
pub mod test_get_storage_contract_storage_proof;
pub mod test_get_transaction_by_hash_declare;
pub mod test_get_transaction_by_hash_deploy;
pub mod test_get_transaction_by_hash_deploy_account;
pub mod test_get_transaction_by_hash_error_txn_hash_not_found;
pub mod test_get_transaction_by_hash_invoke;
pub mod test_get_transaction_status;
pub mod test_get_transaction_status_error_txn_hash_not_found;
pub mod test_get_txn_by_block_id_and_index_declare_v2;
pub mod test_get_txn_by_block_id_and_index_declare_v3;
pub mod test_get_txn_by_block_id_and_index_deploy_account_v1;
pub mod test_get_txn_by_block_id_and_index_deploy_account_v3;
pub mod test_get_txn_receipt_declare;
pub mod test_get_txn_receipt_deploy_account;
pub mod test_simulate_declare_v3_skip_fee;
pub mod test_simulate_declare_v3_skip_validate_skip_fee;
pub mod test_simulate_deploy_account_skip_fee_charge;
pub mod test_simulate_deploy_account_skip_validation_and_fee;
pub mod test_spec_version;
pub mod test_syncing;
pub mod test_trace_block_txn_declare;
pub mod test_trace_block_txn_deploy_acc;

#[derive(Clone, Debug)]
pub struct TestSuiteOpenRpc {
    pub random_paymaster_account: RandomSingleOwnerAccount,
    pub paymaster_private_key: Felt,
    pub random_executable_account: RandomSingleOwnerAccount,
    pub executable_private_key: Felt,
    pub account_class_hash: Felt,
    pub udc_address: Felt,
}

#[derive(Clone, Debug)]
pub struct SetupInput {
    pub urls: Vec<Url>,
    pub paymaster_account_address: Felt,
    pub paymaster_private_key: Felt,
    pub account_class_hash: Felt,
    pub udc_address: Felt,
}

impl SetupableTrait for TestSuiteOpenRpc {
    type Input = SetupInput;

    async fn setup(setup_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (executable_account_flattened_sierra_class, executable_account_compiled_class_hash) =
            get_compiled_contract(
                PathBuf::from_str("target/dev/contracts_MyAccountExec.contract_class.json")?,
                PathBuf::from_str(
                    "target/dev/contracts_MyAccountExec.compiled_contract_class.json",
                )?,
            )
            .await?;

        let provider = JsonRpcClient::new(HttpTransport::new(setup_input.urls[0].clone()));
        let chain_id = get_chain_id(&provider).await?;

        let paymaster_private_key =
            SigningKey::from_secret_scalar(setup_input.paymaster_private_key);

        let mut paymaster_account = SingleOwnerAccount::new(
            provider.clone(),
            LocalWallet::from(paymaster_private_key),
            setup_input.paymaster_account_address,
            chain_id,
            ExecutionEncoding::New,
        );
        paymaster_account.set_block_id(BlockId::Tag(BlockTag::Pending));

        let declare_executable_account_hash = match paymaster_account
            .declare_v3(
                executable_account_flattened_sierra_class.clone(),
                executable_account_compiled_class_hash,
            )
            .send()
            .await
        {
            Ok(result) => {
                wait_for_sent_transaction(result.transaction_hash, &paymaster_account).await?;
                Ok(result.class_hash)
            }
            Err(AccountError::Signing(sign_error)) => {
                if sign_error.to_string().contains("is already declared") {
                    Ok(parse_class_hash_from_error(&sign_error.to_string())?)
                } else {
                    Err(OpenRpcTestGenError::RunnerError(
                        RunnerError::AccountFailure(format!(
                            "Transaction execution error: {}",
                            sign_error
                        )),
                    ))
                }
            }

            Err(AccountError::Provider(ProviderError::Other(starkneterror))) => {
                if starkneterror.to_string().contains("is already declared") {
                    Ok(parse_class_hash_from_error(&starkneterror.to_string())?)
                } else {
                    Err(OpenRpcTestGenError::RunnerError(
                        RunnerError::AccountFailure(format!(
                            "Transaction execution error: {}",
                            starkneterror
                        )),
                    ))
                }
            }
            Err(e) => {
                let full_error_message = format!("{:?}", e);
                if full_error_message.contains("is already declared") {
                    Ok(extract_class_hash_from_error(&full_error_message)?)
                } else {
                    Err(OpenRpcTestGenError::AccountError(AccountError::Other(
                        full_error_message,
                    )))
                }
            }
        }?;

        let executable_account_data = create_account(
            &provider,
            AccountType::Oz,
            Option::None,
            Some(declare_executable_account_hash),
        )
        .await?;

        let deploy_executable_account_call: Call = Call {
            to: setup_input.udc_address,
            selector: get_selector_from_name("deployContract")?,
            calldata: vec![
                declare_executable_account_hash,
                executable_account_data.salt,
                Felt::ZERO,
                Felt::ONE,
                SigningKey::verifying_key(&executable_account_data.signing_key).scalar(),
            ],
        };

        let deploy_executable_account_result = paymaster_account
            .execute_v3(vec![deploy_executable_account_call])
            .send()
            .await?;

        wait_for_sent_transaction(
            deploy_executable_account_result.transaction_hash,
            &paymaster_account,
        )
        .await?;

        let mut executable_account = SingleOwnerAccount::new(
            provider.clone(),
            LocalWallet::from(executable_account_data.signing_key),
            executable_account_data.address,
            chain_id,
            ExecutionEncoding::New,
        );

        executable_account.set_block_id(BlockId::Tag(BlockTag::Pending));

        let mut paymaster_accounts = vec![];
        let mut executable_accounts = vec![];
        for url in &setup_input.urls {
            let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
            let chain_id = get_chain_id(&provider).await?;

            let paymaster_account = SingleOwnerAccount::new(
                provider.clone(),
                LocalWallet::from(paymaster_private_key),
                setup_input.paymaster_account_address,
                chain_id,
                ExecutionEncoding::New,
            );

            let executable_account = SingleOwnerAccount::new(
                provider.clone(),
                LocalWallet::from(executable_account_data.signing_key),
                executable_account_data.address,
                chain_id,
                ExecutionEncoding::New,
            );

            paymaster_accounts.push(paymaster_account);
            executable_accounts.push(executable_account);
        }

        Ok(Self {
            random_executable_account: RandomSingleOwnerAccount {
                accounts: executable_accounts,
            },
            random_paymaster_account: RandomSingleOwnerAccount {
                accounts: paymaster_accounts,
            },
            paymaster_private_key: setup_input.paymaster_private_key,
            executable_private_key: executable_account_data.signing_key.secret_scalar(),
            account_class_hash: setup_input.account_class_hash,
            udc_address: setup_input.udc_address,
        })
    }
}

#[cfg(not(feature = "rust-analyzer"))]
include!(concat!(
    env!("OUT_DIR"),
    "/generated_tests_suite_openrpc.rs"
));
