use std::{path::PathBuf, str::FromStr, vec};

use crate::{
    assert_result,
    utils::{
        v7::{
            accounts::{
                account::{Account, ConnectedAccount},
                call::Call,
            },
            contract::factory::ContractFactory,
            endpoints::{
                declare_contract::get_compiled_contract,
                errors::{CallError, OpenRpcTestGenError},
                utils::{
                    get_selector_from_name, get_storage_var_address, wait_for_sent_transaction,
                },
            },
            providers::provider::Provider,
        },
        v8::types::{ContractStorageKeysItem, MerkleTree, ProofError},
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use starknet_types_core::{
    felt::Felt,
    hash::{Pedersen, StarkHash},
};
use starknet_types_rpc::{BlockId, BlockTag, TxnReceipt};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl22_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl22_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let sender = test_input.random_paymaster_account.random_accounts()?;

        let declare_result = sender
            .declare_v3(flattened_sierra_class, compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declare_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let factory = ContractFactory::new(declare_result.class_hash, sender.clone());
        let mut salt_buffer = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut salt_buffer[1..]);
        let salt = Felt::from_bytes_be(&salt_buffer);
        let unique = true;
        let constructor_calldata = vec![];

        let deployment_result = factory
            .deploy_v3(constructor_calldata, salt, unique)
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

        let contract_balance_slot = get_storage_var_address("balance", &[])?;
        let storage_proof = test_input
            .random_paymaster_account
            .provider()
            .get_storage_proof(
                BlockId::Tag(BlockTag::Latest),
                None,
                None,
                Some(vec![ContractStorageKeysItem {
                    contract_address: deployed_contract_address,
                    storage_keys: vec![contract_balance_slot],
                }]),
            )
            .await?;

        let initial_storage_proof =
            storage_proof
                .contracts_storage_proofs
                .first()
                .ok_or_else(|| {
                    OpenRpcTestGenError::Proof(ProofError::MissingContractStorageProofData {
                        contract_address: deployed_contract_address,
                        slot: contract_balance_slot,
                    })
                })?;

        assert_result!(
            initial_storage_proof.is_empty(),
            "Initial contract storage proof should be empty"
        );

        let balance_increase = Felt::from_hex("0x50")?;
        let increase_balance_call = Call {
            to: deployed_contract_address,
            selector: get_selector_from_name("increase_balance")?,
            calldata: vec![balance_increase],
        };

        let invoke_result = test_input
            .random_paymaster_account
            .execute_v3(vec![increase_balance_call.clone()])
            .send()
            .await?;

        wait_for_sent_transaction(
            invoke_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        let storage_proof = test_input
            .random_paymaster_account
            .provider()
            .get_storage_proof(
                BlockId::Tag(BlockTag::Latest),
                None,
                None,
                Some(vec![ContractStorageKeysItem {
                    contract_address: deployed_contract_address,
                    storage_keys: vec![contract_balance_slot],
                }]),
            )
            .await?;

        let contract_storage_proof = storage_proof
            .contracts_storage_proofs
            .first()
            .cloned()
            .ok_or_else(|| {
                OpenRpcTestGenError::Proof(ProofError::MissingContractStorageProofData {
                    contract_address: deployed_contract_address,
                    slot: contract_balance_slot,
                })
            })?;

        let merkle_tree = MerkleTree::from_proof(contract_storage_proof, None);
        let expected_child = balance_increase;

        let valid_proof = merkle_tree.verify_proof(&expected_child, Pedersen::hash)?;
        assert_result!(valid_proof, "Contract storage proof verification failed");

        Ok(Self {})
    }
}
