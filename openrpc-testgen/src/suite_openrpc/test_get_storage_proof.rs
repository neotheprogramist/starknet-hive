use std::{path::PathBuf, str::FromStr};

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
        v8::types::MerkleTreeMadara,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use starknet::macros::short_string;
use starknet_types_core::{
    felt::Felt,
    hash::{Poseidon, StarkHash},
};
use starknet_types_rpc::{BlockId, BlockTag, FunctionCall, TxnReceipt};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl15_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl15_HelloStarknet.compiled_contract_class.json",
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

        // Step 1: Call the deployed contract
        let initial_balance = *test_input
            .random_paymaster_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![],
                    contract_address: deployed_contract_address,
                    entry_point_selector: get_selector_from_name("get_balance")?,
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await?
            .first()
            .ok_or(OpenRpcTestGenError::Other(
                "Empty initial contract balance".to_string(),
            ))?;

        // Step 2: Get the storage value and get the storage value
        let contract_balance_slot = get_storage_var_address("balance", &[])?;

        let initial_storage_value = test_input
            .random_paymaster_account
            .provider()
            .get_storage_at(
                deployed_contract_address,
                contract_balance_slot,
                BlockId::Tag(BlockTag::Latest),
            )
            .await?;

        // Step 3: Update the storage value
        let balance_increase = Felt::from_hex("0x50")?;
        let increase_balance_call = Call {
            to: deployed_contract_address,
            selector: get_selector_from_name("increase_balance")?,
            calldata: vec![balance_increase],
        };

        let invoke_result = test_input
            .random_paymaster_account
            .execute_v3(vec![increase_balance_call])
            .send()
            .await?;

        wait_for_sent_transaction(
            invoke_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        // Step 4: Get the updated balance via call and get the updated storage value
        let updated_balance = *test_input
            .random_paymaster_account
            .provider()
            .call(
                FunctionCall {
                    calldata: vec![],
                    contract_address: deployed_contract_address,
                    entry_point_selector: get_selector_from_name("get_balance")?,
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await?
            .first()
            .ok_or(OpenRpcTestGenError::Other(
                "Empty updated contract balance".to_string(),
            ))?;

        let updated_storage_value = test_input
            .random_paymaster_account
            .provider()
            .get_storage_at(
                deployed_contract_address,
                contract_balance_slot,
                BlockId::Tag(BlockTag::Latest),
            )
            .await;

        // Step 5: Assert the updated balance and storage value
        let result = updated_storage_value.is_ok();
        assert_result!(result);

        let updated_storage_value = updated_storage_value?;

        assert_result!(
            updated_balance == initial_balance + balance_increase,
            format!(
                "Mismatch in updated balance. Expected: {}, Found: {}.",
                balance_increase, updated_balance
            )
        );

        assert_result!(
            updated_storage_value == initial_storage_value + balance_increase,
            format!(
                "Mismatch in updated storage value. Expected: {}, Found: {}.",
                balance_increase, updated_storage_value
            )
        );

        assert_result!(
            updated_storage_value == updated_balance,
            format!(
                "Updated storage value doesnt match updated balance. Updated storage value: {}, Updated balance: {}.",
                updated_storage_value, updated_balance
            )
        );

        println!("class_hash {:#?}", declare_result.class_hash);
        println!("compiled class_hash {:#?}", compiled_class_hash);

        println!("deployed_contract_address {:#?}", deployed_contract_address,);

        println!("contract_balance_slot {:#?}", contract_balance_slot);
        println!(
            "poseidon class hash compiled class hash {:#?}",
            Poseidon::hash(&declare_result.class_hash, &compiled_class_hash)
        );

        // println!(
        //     "poseidon CONTRACT_CLASS_LEAF_V0 compiled class hash {:#?}",
        //     Poseidon::hash(
        //         &Felt::from_hex_unchecked("CONTRACT_CLASS_LEAF_V0"),
        //         &compiled_class_hash
        //     )
        // );
        const CONTRACT_CLASS_LEAF_V0: Felt = short_string!("CONTRACT_CLASS_LEAF_V0");
        println!(
            "poseidon macro! CONTRACT_CLASS_LEAF_V0 compiled class hash {:#?}",
            Poseidon::hash(&CONTRACT_CLASS_LEAF_V0, &compiled_class_hash)
        );
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

        println!("storage_proof {:#?}", storage_proof);

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

        println!("storage_proof {:#?}", storage_proof);

        let merkle_tree = MerkleTreeMadara::from_proof(
            storage_proof.classes_proof,
            storage_proof.global_roots.classes_tree_root,
        );
        merkle_tree.compute_edge_hash();

        // assert_result!(is_valid_poseidon, "Poseidon proof invalid!");

        // // Weryfikacja dowodu Merkle'a za pomocą Pedersena
        // let is_valid_pedersen = verify_merkle_proof(
        //     declare_result.class_hash,
        //     storage_proof.classes_proof,
        //     storage_proof.global_roots.classes_tree_root,
        //     Pedersen::hash,
        // );

        // assert_result!(is_valid_pedersen, "Pedersen proof invalid!");

        // println!(
        //     "Expected root hash: {:#?}",
        //     storage_proof.global_roots.classes_tree_root
        // );

        // Sprawdzamy, czy obliczony root zgadza się z `classes_tree_root`
        // assert!(
        //     computed_root_poseidon == storage_proof.global_roots.classes_tree_root,
        //     "Poseidon proof invalid!"
        // );
        // assert!(
        //     computed_root_pedersen == storage_proof.global_roots.classes_tree_root,
        //     "Pedersen proof invalid!"
        // );

        Ok(Self {})
    }
}
