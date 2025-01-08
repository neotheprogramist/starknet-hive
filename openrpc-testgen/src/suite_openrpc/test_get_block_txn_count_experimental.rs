use std::{path::PathBuf, str::FromStr};

use crate::{
    assert_result,
    utils::v7::{
        accounts::account::{Account, ConnectedAccount},
        contract::factory::ContractFactory,
        endpoints::{
            declare_contract::get_compiled_contract, errors::OpenRpcTestGenError,
            utils::wait_for_sent_transaction,
        },
        providers::provider::{self, Provider},
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        println!("XD1");
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl4_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl4_HelloStarknet.compiled_contract_class.json",
            )?,
        )
        .await?;

        let declaration_result = test_input
            .random_paymaster_account
            .declare_v3(flattened_sierra_class, compiled_class_hash)
            .send()
            .await?;

        wait_for_sent_transaction(
            declaration_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        println!("XD2");

        let mut txn_count = 0;
        let paymaster_account = test_input.random_paymaster_account.random_accounts()?;

        let factory =
            ContractFactory::new(declaration_result.class_hash, paymaster_account.clone());

        let mut salt_buffer = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut salt_buffer[1..]);

        let mut initial_nonce = paymaster_account
            .provider()
            .get_nonce(BlockId::Tag(BlockTag::Pending), paymaster_account.address())
            .await?;
        println!("ACC NONCE {:?}", initial_nonce);

        let initial_block_number = test_input
            .random_paymaster_account
            .provider()
            .block_number()
            .await?;

        println!("XD3");

        loop {
            println!("loop {}", txn_count);
            println!("ACC NONCE START LOOP {}", initial_nonce);

            factory
                .deploy_v3(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .nonce(initial_nonce)
                .send()
                .await?;

            txn_count += 1;

            initial_nonce = paymaster_account
                .provider()
                .get_nonce(BlockId::Tag(BlockTag::Pending), paymaster_account.address())
                .await?;

            println!("Updated NONCE after transaction: {}", initial_nonce);

            let current_block_number = test_input
                .random_paymaster_account
                .provider()
                .block_number()
                .await?;

            if current_block_number > initial_block_number {
                println!("Breaking loop");
                break;
            }
        }

        let block_txn_count = test_input
            .random_paymaster_account
            .provider()
            .get_block_transaction_count(BlockId::Number(initial_block_number))
            .await;

        let result = block_txn_count.is_ok();

        assert_result!(result);

        let block_txn_count = block_txn_count?;
        assert_result!(
            block_txn_count == txn_count,
            format!(
                "Mismatch in transaction count. Expected: {}, Found: {}.",
                txn_count, block_txn_count
            )
        );

        Ok(Self {})
    }
}
