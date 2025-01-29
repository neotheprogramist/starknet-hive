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

use crate::utils::starknet_hive::StarknetHive;

// pub mod suite_deploy;
pub mod test_block_hash_and_number;
pub mod test_declare_txn_v2;
pub mod test_declare_txn_v3;
pub mod test_declare_v3_trace;
// pub mod test_deploy_account_outside_execution;
pub mod test_deploy_account_trace;
// pub mod test_deploy_account_v1;
// pub mod test_deploy_account_v3;
// pub mod test_erc20_transfer_outside_execution;
// pub mod test_estimate_fee_fri;
// pub mod test_estimate_fee_wei;
// pub mod test_get_block_number;
// pub mod test_get_block_txn_count;
// pub mod test_get_block_with_receipts_declare;
// pub mod test_get_block_with_receipts_deploy;
// pub mod test_get_block_with_receipts_deploy_account;
// pub mod test_get_block_with_receipts_invoke;
// pub mod test_get_block_with_tx_hashes;
// pub mod test_get_block_with_txs;
// pub mod test_get_chain_id;
// pub mod test_get_class;
// pub mod test_get_events_declare;
// pub mod test_get_events_deploy;
// pub mod test_get_events_deploy_account;
// pub mod test_get_events_transfer;
// pub mod test_get_nonce;
// pub mod test_get_state_update;
// pub mod test_get_transaction_by_hash_declare;
// pub mod test_get_transaction_by_hash_deploy;
// pub mod test_get_transaction_by_hash_deploy_account;
// pub mod test_get_transaction_by_hash_error_txn_hash_not_found;
// pub mod test_get_transaction_by_hash_invoke;
// pub mod test_get_transaction_status;
// pub mod test_get_transaction_status_error_txn_hash_not_found;
// pub mod test_get_txn_by_block_id_and_index_declare_v2;
// pub mod test_get_txn_by_block_id_and_index_declare_v3;
// pub mod test_get_txn_by_block_id_and_index_deploy_account_v1;
// pub mod test_get_txn_by_block_id_and_index_deploy_account_v3;
// pub mod test_get_txn_receipt_declare;
// pub mod test_get_txn_receipt_deploy_account;
// pub mod test_simulate_declare_v3_skip_fee;
// pub mod test_simulate_declare_v3_skip_validate_skip_fee;
// pub mod test_simulate_deploy_account_skip_fee_charge;
// pub mod test_simulate_deploy_account_skip_validation_and_fee;
// pub mod test_spec_version;
// pub mod test_syncing;
// pub mod test_trace_block_txn_declare;
// pub mod test_trace_block_txn_deploy_acc;

#[derive(Clone, Debug)]
pub struct TestSuiteOpenRpc {
    hive: StarknetHive,
    account_class_hash: Felt,
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
        let hive = StarknetHive::new(
            setup_input.urls[0].clone(),
            setup_input.paymaster_account_address,
            setup_input.paymaster_private_key,
            setup_input.account_class_hash,
        )
        .await?;

        Ok(Self {
            hive,
            account_class_hash: setup_input.account_class_hash,
        })
    }
}

#[cfg(not(feature = "rust-analyzer"))]
include!(concat!(
    env!("OUT_DIR"),
    "/generated_tests_suite_openrpc.rs"
));
