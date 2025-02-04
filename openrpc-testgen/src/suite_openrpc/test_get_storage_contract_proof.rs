use std::{path::PathBuf, str::FromStr, vec};

use crate::{
    assert_result,
    utils::{
        v7::{
            accounts::account::{Account, ConnectedAccount},
            contract::factory::ContractFactory,
            endpoints::{
                declare_contract::get_compiled_contract,
                errors::{CallError, OpenRpcTestGenError},
                utils::wait_for_sent_transaction,
            },
            providers::provider::Provider,
        },
        v8::types::{MerkleTree, ProofError},
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
                "target/dev/contracts_contracts_smpl21_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl21_HelloStarknet.compiled_contract_class.json",
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

        let contract_nonce = test_input
            .random_paymaster_account
            .provider()
            .get_nonce(BlockId::Tag(BlockTag::Latest), deployed_contract_address)
            .await?;

        let storage_proof = test_input
            .random_paymaster_account
            .provider()
            .get_storage_proof(
                BlockId::Tag(BlockTag::Latest),
                None,
                Some(vec![deployed_contract_address]),
                None,
            )
            .await?;

        let contract_proof_leaves_data_item = storage_proof
            .contracts_proof
            .contract_leaves_data
            .first()
            .ok_or_else(|| {
                OpenRpcTestGenError::Proof(ProofError::MissingContractLeavesData {
                    contract_address: deployed_contract_address,
                })
            })?;

        let nonce = contract_proof_leaves_data_item.nonce;
        let class_hash = contract_proof_leaves_data_item.class_hash;

        assert_result!(
            nonce == contract_nonce,
            format!("Expected nonce {:?} but got {:?}", contract_nonce, nonce)
        );

        assert_result!(
            class_hash == declare_result.class_hash,
            format!(
                "Expected class hash {:?} but got {:?}",
                declare_result.class_hash, class_hash
            )
        );

        let merkle_tree = MerkleTree::from_proof(
            storage_proof.contracts_proof.nodes,
            Some(storage_proof.global_roots.contracts_tree_root),
        );
        let expected_child =
            merkle_tree.compute_expected_child_for_contract_proof(&class_hash, &Felt::ZERO, &nonce);

        let valid_proof = merkle_tree.verify_proof(&expected_child, Pedersen::hash)?;
        assert_result!(valid_proof, "Contract proof verification failed");

        Ok(Self {})
    }
}
