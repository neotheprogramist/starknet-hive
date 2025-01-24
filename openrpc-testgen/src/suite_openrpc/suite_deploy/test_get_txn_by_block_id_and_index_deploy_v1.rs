use crate::{
    assert_result,
    utils::v7::{
        accounts::account::{starknet_keccak, Account, ConnectedAccount},
        contract::factory::ContractFactory,
        endpoints::{errors::OpenRpcTestGenError, utils::wait_for_sent_transaction},
        providers::provider::Provider,
    },
    RandomizableAccountsTrait, RunnableTrait,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{
    BlockId, BroadcastedInvokeTxn, BroadcastedTxn, InvokeTxn, MaybePendingBlockWithTxs, Txn,
};
use t9n::txn_validation::invoke::verify_invoke_v1_signature;
const UDC_ADDRESS: Felt =
    Felt::from_hex_unchecked("0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf");
const MAX_FEE: Felt = Felt::from_hex_unchecked("0x2977");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteDeploy;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let class_hash = test_input.declaration_result.class_hash;
        let sender = test_input.random_paymaster_account.random_accounts()?;
        let sender_nonce = sender.get_nonce().await?;
        let sender_address = sender.address();
        let factory = ContractFactory::new(class_hash, sender.clone());
        let mut salt_buffer = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut salt_buffer[1..]);
        let salt = Felt::from_bytes_be(&salt_buffer);
        let unique = true;
        let constructor_calldata = vec![];

        let deploy_request = factory
            .deploy_v1(constructor_calldata.clone(), salt, unique)
            .max_fee(MAX_FEE)
            .prepare_execute()
            .await?
            .get_invoke_request(false, false)
            .await?;

        let signature = deploy_request.clone().signature;

        let (valid_signature, deploy_hash) = verify_invoke_v1_signature(
            &deploy_request,
            None,
            sender
                .clone()
                .provider()
                .chain_id()
                .await?
                .to_hex_string()
                .as_str(),
        )?;

        let deploy_result = test_input
            .random_paymaster_account
            .provider()
            .add_invoke_transaction(BroadcastedTxn::Invoke(BroadcastedInvokeTxn::V1(
                deploy_request,
            )))
            .await?;

        wait_for_sent_transaction(
            deploy_result.transaction_hash,
            &test_input.random_paymaster_account.random_accounts()?,
        )
        .await?;

        assert_result!(
            deploy_result.transaction_hash == deploy_hash,
            format!(
                "Exptected transaction hash to be {:?}, got {:?}",
                deploy_hash, deploy_result.transaction_hash
            )
        );

        let block_number = test_input
            .random_paymaster_account
            .provider()
            .block_hash_and_number()
            .await?
            .block_number;

        let block_with_txns = test_input
            .random_paymaster_account
            .provider()
            .get_block_with_txs(BlockId::Number(block_number))
            .await?;

        let txn_index: u64 = match block_with_txns {
            MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs
                .transactions
                .iter()
                .position(|tx| tx.transaction_hash == deploy_result.transaction_hash)
                .ok_or_else(|| {
                    OpenRpcTestGenError::TransactionNotFound(
                        deploy_result.transaction_hash.to_string(),
                    )
                })?
                .try_into()
                .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
            MaybePendingBlockWithTxs::Pending(block_with_txs) => block_with_txs
                .transactions
                .iter()
                .position(|tx| tx.transaction_hash == deploy_result.transaction_hash)
                .ok_or_else(|| {
                    OpenRpcTestGenError::TransactionNotFound(
                        deploy_result.transaction_hash.to_string(),
                    )
                })?
                .try_into()
                .map_err(|_| OpenRpcTestGenError::TransactionIndexOverflow)?,
        };

        let txn = test_input
            .random_paymaster_account
            .provider()
            .get_transaction_by_block_id_and_index(BlockId::Number(block_number), txn_index)
            .await?;

        let txn = match txn {
            Txn::Invoke(InvokeTxn::V1(txn)) => txn,
            _ => {
                let error_message = format!("Unexpected transaction response type: {:?}", txn);
                return Err(OpenRpcTestGenError::UnexpectedTxnType(error_message));
            }
        };

        assert_result!(
            txn.calldata.len() == 8,
            format!("Expected calldata len 8, got {:#?} ", txn.calldata.len())
        );

        let calldata_first = *txn.calldata.first().ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing first calldata element".to_string())
        })?;

        let calls_amount = Felt::ONE;
        assert_result!(
            calldata_first == calls_amount,
            format!(
                "Expected first calldata element to be {:#?}, got {:#?} ",
                calls_amount, calldata_first
            )
        );

        let calldata_second = *txn.calldata.get(1).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;

        assert_result!(
            calldata_second == UDC_ADDRESS,
            format!(
                "Expected second calldata element to be {:#?}, got {:#?}",
                UDC_ADDRESS, calldata_second
            )
        );

        let calldata_third = *txn.calldata.get(2).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;
        let keccak_deploy_contract = starknet_keccak("deployContract".as_bytes());

        assert_result!(
            calldata_third == keccak_deploy_contract,
            format!(
                "Expected third calldata element to be {:#?}, got {:#?}",
                keccak_deploy_contract, calldata_third
            )
        );

        let calldata_fourth = *txn.calldata.get(3).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;
        let expected_calldata_call_length = Felt::from_hex("0x4")?;
        assert_result!(
            calldata_fourth == expected_calldata_call_length,
            format!(
                "Expected fourth calldata element to be {:#?}, got {:#?}",
                expected_calldata_call_length, calldata_fourth
            )
        );

        let calldata_fifth = *txn.calldata.get(4).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;

        assert_result!(
            calldata_fifth == class_hash,
            format!(
                "Expected fifth calldata element to be {:#?}, got {:#?}",
                class_hash, calldata_fifth
            )
        );

        let calldata_sixth = *txn.calldata.get(5).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;

        assert_result!(
            calldata_sixth == salt,
            format!(
                "Expected sixth calldata element to be {:#?}, got {:#?}",
                salt, calldata_sixth
            )
        );

        let calldata_seventh = *txn.calldata.get(6).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;

        let unique_hex = match unique {
            true => Felt::ONE,
            false => Felt::ZERO,
        };

        assert_result!(
            calldata_seventh == unique_hex,
            format!(
                "Expected seventh calldata element to be {:#?}, got {:#?}",
                unique_hex, calldata_seventh
            )
        );

        let calldata_eight = *txn.calldata.get(7).ok_or_else(|| {
            OpenRpcTestGenError::Other("Missing last calldata element".to_string())
        })?;
        let contructor_calldata_len_hex =
            Felt::from_dec_str(&constructor_calldata.len().to_string())?;
        assert_result!(
            calldata_eight == contructor_calldata_len_hex,
            format!(
                "Expected eigth calldata element to be {:#?}, got {:#?}",
                contructor_calldata_len_hex, calldata_eight
            )
        );

        assert_result!(
            txn.max_fee == MAX_FEE,
            format!(
                "Expected max fee to be {:#?}, got {:#?}",
                MAX_FEE, txn.max_fee
            )
        );

        assert_result!(
            txn.nonce == sender_nonce,
            format!(
                "Expected nonce to be {:#?}, got {:#?}",
                sender_nonce, txn.nonce
            )
        );

        assert_result!(
            txn.sender_address == sender_address,
            format!(
                "Expected sender address to be {:#?}, got {:#?} ",
                sender_address, txn.sender_address
            )
        );

        assert_result!(
            valid_signature,
            format!("Invalid signature, checked by t9n.",)
        );

        assert_result!(
            txn.signature == signature,
            format!(
                "Expected signature: {:?}, got {:?}",
                signature, txn.signature
            )
        );

        Ok(Self {})
    }
}
