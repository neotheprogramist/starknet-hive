use std::{path::PathBuf, str::FromStr};

use crate::{
    assert_result,
    utils::v7::{
        accounts::{
            account::{Account, ConnectedAccount},
            call::Call,
        },
        contract::factory::ContractFactory,
        endpoints::{
            declare_contract::get_compiled_contract,
            errors::{CallError, OpenRpcTestGenError},
            utils::{get_selector_from_name, wait_for_sent_transaction},
        },
        providers::provider::Provider,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, TxnReceipt};

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteOpenRpc;

    /// This test case checks if the get_block_transaction_count endpoint returns the correct number of transactions in a block.
    ///
    /// It first deploys a contract, then performs a multicall to the contract.
    /// After the invocations, it waits for a new block to be mined.
    /// The test then checks if the correct number of transactions is returned by the get_block_transaction_count endpoint.
    ///
    /// The test case fails if the number of transactions returned by the endpoint does not match the number of transactions sent.
    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        // Step 1: Declare the contract
        let (flattened_sierra_class, compiled_class_hash) = get_compiled_contract(
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl5_HelloStarknet.contract_class.json",
            )?,
            PathBuf::from_str(
                "target/dev/contracts_contracts_smpl5_HelloStarknet.compiled_contract_class.json",
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

        // Step 2: Deploy the declared contract
        let paymaster_account = test_input.random_paymaster_account.random_accounts()?;

        let factory =
            ContractFactory::new(declaration_result.class_hash, paymaster_account.clone());

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

        // Step 3: Retrieve the deployed contract address
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

        // Step 4: Prepare to invoke the contract
        let increase_balance_call = Call {
            to: deployed_contract_address,
            selector: get_selector_from_name("increase_balance")?,
            calldata: vec![Felt::from_hex("0x50")?],
        };

        let txn_count = rand::thread_rng().gen_range(3..=10);
        let calls: Vec<Call> = vec![increase_balance_call; txn_count];

        // Step 5: Wait for a new block to start with a clean slate
        let initial_block_number = test_input
            .random_paymaster_account
            .provider()
            .block_number()
            .await?;
        loop {
            let current_block_number = test_input
                .random_paymaster_account
                .provider()
                .block_number()
                .await?;
            if current_block_number > initial_block_number {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        // Step 6: Execute transactions
        let invoke_result = test_input
            .random_paymaster_account
            .execute_v3(calls)
            .send()
            .await?;

        wait_for_sent_transaction(
            invoke_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        // Step 7: Verify the transaction count in the block and if the response is ok
        let block_txn_count = test_input
            .random_paymaster_account
            .provider()
            .get_block_transaction_count(BlockId::Number(initial_block_number))
            .await;

        let result = block_txn_count.is_ok();

        assert_result!(result);

        let block_txn_count = block_txn_count?;

        assert_result!(
            block_txn_count == 1,
            format!(
                "Mismatch in transaction count. Expected: {}, Found: {}.",
                1, block_txn_count
            )
        );

        Ok(Self {})
    }
}
