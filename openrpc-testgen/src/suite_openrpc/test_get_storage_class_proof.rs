use std::{path::PathBuf, str::FromStr};

use crate::{
    assert_result,
    utils::{
        v7::{
            accounts::account::{Account, ConnectedAccount},
            endpoints::{
                declare_contract::get_compiled_contract, errors::OpenRpcTestGenError,
                utils::wait_for_sent_transaction,
            },
            providers::provider::Provider,
        },
        v8::types::MerkleTree,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use starknet_types_core::hash::{Poseidon, StarkHash};
use starknet_types_rpc::{BlockId, BlockTag};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl20_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl20_HelloStarknet.compiled_contract_class.json",
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

        let storage_proof = test_input
            .random_paymaster_account
            .provider()
            .get_storage_proof(
                BlockId::Tag(BlockTag::Latest),
                Some(vec![declare_result.class_hash]),
                None,
                None,
            )
            .await?;

        let merkle_tree = MerkleTree::from_proof(
            storage_proof.classes_proof,
            Some(storage_proof.global_roots.classes_tree_root),
        );

        let expected_child =
            merkle_tree.compute_expected_child_for_class_proof(&compiled_class_hash);
        let valid_proof = merkle_tree.verify_proof(&expected_child, Poseidon::hash)?;
        assert_result!(valid_proof, "Class proof verification failed");

        Ok(Self {})
    }
}
