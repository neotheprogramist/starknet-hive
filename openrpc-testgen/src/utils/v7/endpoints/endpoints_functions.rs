use std::sync::Arc;

use cainome_cairo_serde::CairoSerde;
use cainome_cairo_serde_derive::CairoSerde;
use rand::{rngs::StdRng, RngCore, SeedableRng};

use starknet::core::crypto::ecdsa_sign;
use starknet_types_core::{
    felt::Felt,
    hash::{Poseidon, StarkHash},
};
use starknet_types_rpc::{
    v0_7_1::{
        AddInvokeTransactionResult, BlockId, BlockTag, BlockWithTxHashes, BlockWithTxs,
        ContractClass, DeployAccountTxn, DeployAccountTxnV3, FeeEstimate, FunctionCall, InvokeTxn,
        InvokeTxnV1, MaybePendingBlockWithTxHashes, MaybePendingBlockWithTxs,
        MaybePendingStateUpdate, StateUpdate, Txn, TxnExecutionStatus, TxnReceipt, TxnStatus,
    },
    DeclareTxn, DeployTxn, InvokeTxnReceipt, MsgFromL1,
};

use tracing::{info, warn};
use url::Url;

use crate::utils::v7::{
    accounts::{
        account::{Account, AccountError, ConnectedAccount},
        call::Call,
        creation::{
            create::{create_account, AccountType},
            helpers::get_chain_id,
        },
        deployment::{
            deploy::{deploy_account, DeployAccountVersion},
            structs::{ValidatedWaitParams, WaitForTx},
        },
        single_owner::{ExecutionEncoding, SingleOwnerAccount},
    },
    contract::factory::ContractFactory,
    endpoints::{declare_contract::extract_class_hash_from_error, errors::CallError},
    providers::{
        jsonrpc::{HttpTransport, JsonRpcClient, StarknetError},
        provider::{Provider, ProviderError},
    },
    signers::{key_pair::SigningKey, local_wallet::LocalWallet},
};

use super::{
    declare_contract::{parse_class_hash_from_error, RunnerError},
    errors::OpenRpcTestGenError,
    utils::{
        get_compiled_contract, get_selector_from_name, setup_generated_account, validate_inputs,
        wait_for_sent_transaction,
    },
};

#[allow(clippy::too_many_arguments)]
pub async fn invoke_contract_erc20_transfer(
    url: Url,
    _sierra_path: &str,
    _casm_path: &str,
    _account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<Felt, OpenRpcTestGenError> {
    let (executable_account_flattened_sierra_class, executable_account_compiled_class_hash) =
        get_compiled_contract(
            "target/dev/contracts_MyAccount.contract_class.json",
            "target/dev/contracts_MyAccount.compiled_contract_class.json",
        )
        .await?;

    let (erc_20_flattened_sierra_class, erc_20_compiled_class_hash) = get_compiled_contract(
        "target/dev/contracts_TestToken.contract_class.json",
        "target/dev/contracts_TestToken.compiled_contract_class.json",
    )
    .await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));

    let (
        account_address,
        private_key,
        _erc20_strk_contract_address,
        _erc20_eth_contract_address,
        _amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let paymaster_signing_key = SigningKey::from_secret_scalar(private_key);
    let paymaster_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(paymaster_signing_key),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    // TODO DECLARE EXEC ACC
    let declaration_hash_executable_account = match paymaster_account
        .declare_v3(
            executable_account_flattened_sierra_class,
            executable_account_compiled_class_hash,
        )
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            info!("error {:?}", full_error_message);
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };

    let exec_hash = declaration_hash_executable_account.unwrap();

    // TODO EXECUTABLE ACCOUNT DATA (address, signing_key etc.)
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, Some(exec_hash)).await?;

    // deploy new account via udc
    let udc_deploy_account_call = Call {
        to: Felt::from_hex("0x41A78E741E5AF2FEC34B695679BC6891742439F7AFB8484ECD7766661AD02BF")?,
        selector: get_selector_from_name("deployContract")?,
        calldata: vec![
            exec_hash,
            create_acc_data.salt,
            Felt::ZERO,
            Felt::ONE,
            SigningKey::verifying_key(&create_acc_data.signing_key).scalar(),
        ],
    };

    let deploy_acc_via_payamster_result = paymaster_account
        .execute_v1(vec![udc_deploy_account_call])
        .send()
        .await?;

    wait_for_sent_transaction(
        deploy_acc_via_payamster_result.transaction_hash,
        &paymaster_account,
    )
    .await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut executable_account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    executable_account.set_block_id(BlockId::Tag(BlockTag::Pending));

    // // DECLARE ERC20
    let declaration_hash = match paymaster_account
        .declare_v2(
            Arc::new(erc_20_flattened_sierra_class),
            erc_20_compiled_class_hash,
        )
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };
    // // DEPLOY ERC20
    let deployment_hash_erc20 = match declaration_hash {
        Ok(class_hash) => {
            let factory = ContractFactory::new(class_hash, paymaster_account.clone());
            let mut salt_buffer = [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt_buffer[1..]);

            let result = factory
                .deploy_v1(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .max_fee(Felt::from_dec_str("100000000000000000")?)
                .send()
                .await?;

            wait_for_sent_transaction(result.transaction_hash, &paymaster_account).await?;
            Ok(result.transaction_hash)
        }
        Err(e) => Err(e),
    };

    let deployment_receipt_erc20 = match deployment_hash_erc20 {
        Ok(hash) => provider.get_transaction_receipt(hash).await?,
        Err(e) => {
            return Err(e);
        }
    };

    let contract_address_erc20 = match deployment_receipt_erc20 {
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

    // // TODO MINT TOKENS FOR EEXCUTABLE
    let erc20_mint_call = Call {
        to: contract_address_erc20,
        selector: get_selector_from_name("mint")?,
        calldata: vec![
            executable_account.address(),
            Felt::from_hex("0x123")?,
            Felt::ZERO,
        ],
    };

    paymaster_account
        .execute_v1(vec![erc20_mint_call])
        .send()
        .await?;

    // // TODO PREPARE TRANSFER CALL TO ERC20
    let account_erc20_receiver_address =
        Felt::from_hex("0x78662e7352d062084b0010068b99288486c2d8b914f6e2a55ce945f8792c8b1")?;
    let amount_to_transfer = vec![Felt::from_hex("0x100")?, Felt::ZERO];

    let erc20_transfer_call = Call {
        to: contract_address_erc20,
        selector: get_selector_from_name("transfer")?,
        calldata: vec![
            account_erc20_receiver_address,
            amount_to_transfer[0],
            amount_to_transfer[1],
        ],
    };

    // // TODO PREPARE OUTSIDE EXECUTION
    let outside_execution = OutsideExecution {
        caller: paymaster_account.address(), // paymaster
        nonce: Felt::ZERO,
        calls: vec![erc20_transfer_call],
    };

    // get outside execution hash
    let outside_execution_cairo_serialized = &OutsideExecution::cairo_serialize(&outside_execution);

    let hash = Poseidon::hash_array(outside_execution_cairo_serialized);

    let starknet::core::crypto::ExtendedSignature { r, s, v: _ } =
        ecdsa_sign(&private_key, &hash).unwrap();

    // struct sign - vector1.expand(vector2);
    let mut calldata_to_executable_account_call = outside_execution_cairo_serialized.clone();
    calldata_to_executable_account_call.push(Felt::from_dec_str("2")?);
    calldata_to_executable_account_call.push(r);
    calldata_to_executable_account_call.push(s);

    let call_to_executable_account = Call {
        to: executable_account.address(),
        selector: get_selector_from_name("execute_from_outside")?,
        calldata: calldata_to_executable_account_call,
    };

    paymaster_account
        .execute_v1(vec![call_to_executable_account])
        .send()
        .await?;

    // CHECK BALANCE
    let balance_after_txn = provider
        .call(
            FunctionCall {
                calldata: vec![account_erc20_receiver_address],
                contract_address: contract_address_erc20,
                entry_point_selector: get_selector_from_name("balance_of")?,
            },
            BlockId::Tag(BlockTag::Pending),
        )
        .await?;
    assert!(
        balance_after_txn == amount_to_transfer,
        "BALANCES DO NOT MATCH"
    );

    Ok(Felt::ONE)
}

#[derive(Debug, CairoSerde)]
pub struct OutsideExecution {
    pub caller: Felt,
    pub nonce: Felt,
    pub calls: Vec<Call>,
}

#[allow(clippy::too_many_arguments)]
pub async fn add_declare_transaction_v2(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<Felt, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        match create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await {
            Ok(value) => value,
            Err(e) => {
                warn!("{}", "Could not create an account");
                return Err(e.into());
            }
        };

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;
    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        provider,
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    match account
        .declare_v2(Arc::new(flattened_sierra_class), compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
        Err(e) => Err(OpenRpcTestGenError::RunnerError(
            RunnerError::AccountFailure(format!("Account error: {}", e)),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn add_declare_transaction_v3(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<Felt, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        match create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await {
            Ok(value) => value,
            Err(e) => {
                warn!("{}", "Could not create an account");
                return Err(e.into());
            }
        };

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    match account
        .declare_v3(flattened_sierra_class, compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
        Err(e) => Err(OpenRpcTestGenError::RunnerError(
            RunnerError::AccountFailure(format!("Account error: {}", e)),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn add_invoke_transaction_v1(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<AddInvokeTransactionResult<Felt>, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let declare_contract_hash = match account
        .declare_v2(Arc::new(flattened_sierra_class), compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };
    match declare_contract_hash {
        Ok(class_hash) => {
            let factory = ContractFactory::new(class_hash, account);
            let mut salt_buffer = [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt_buffer[1..]);
            let result = factory
                .deploy_v1(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .max_fee(Felt::from_dec_str("100000000000000000")?)
                .send()
                .await?;
            Ok(result)
        }
        Err(e) => Err(e),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn add_invoke_transaction_v3(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<AddInvokeTransactionResult<Felt>, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let declare_contract_hash = match account
        .declare_v3(flattened_sierra_class, compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };
    match declare_contract_hash {
        Ok(class_hash) => {
            let factory = ContractFactory::new(class_hash, account);
            let mut salt_buffer = [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt_buffer[1..]);
            let result = factory
                .deploy_v3(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .send()
                .await?;
            Ok(result)
        }
        Err(e) => Err(e),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn invoke_contract_v1(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<AddInvokeTransactionResult<Felt>, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let declaration_hash = match account
        .declare_v2(Arc::new(flattened_sierra_class), compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };
    let deployment_hash = match declaration_hash {
        Ok(class_hash) => {
            let factory = ContractFactory::new(class_hash, account.clone());
            let mut salt_buffer = [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt_buffer[1..]);

            let result = factory
                .deploy_v1(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .max_fee(Felt::from_dec_str("100000000000000000")?)
                .send()
                .await?;

            wait_for_sent_transaction(result.transaction_hash, &user_passed_account).await?;
            Ok(result.transaction_hash)
        }
        Err(e) => Err(e),
    };

    let deployment_receipt = match deployment_hash {
        Ok(hash) => provider.get_transaction_receipt(hash).await?,
        Err(e) => {
            return Err(e);
        }
    };

    let contract_address = match deployment_receipt {
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

    let call = Call {
        to: contract_address,
        selector: get_selector_from_name("increase_balance")?,
        calldata: vec![Felt::from_hex("0x50")?],
    };

    let invoke_contract_fn_result = account.execute_v1(vec![call]).send().await?;
    Ok(invoke_contract_fn_result)
}

#[allow(clippy::too_many_arguments)]
pub async fn invoke_contract_v3(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<AddInvokeTransactionResult<Felt>, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let declare_contract_hash = match account
        .declare_v3(flattened_sierra_class, compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };

    let deployment_hash = match declare_contract_hash {
        Ok(class_hash) => {
            let factory = ContractFactory::new(class_hash, account.clone());
            let mut salt_buffer = [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt_buffer[1..]);

            let result = factory
                .deploy_v3(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .send()
                .await?;
            wait_for_sent_transaction(result.transaction_hash, &user_passed_account).await?;
            Ok(result.transaction_hash)
        }
        Err(e) => Err(e),
    };

    let deployment_receipt = match deployment_hash {
        Ok(hash) => provider.get_transaction_receipt(hash).await?,
        Err(e) => {
            return Err(e);
        }
    };

    let contract_address = match deployment_receipt {
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

    let call = Call {
        to: contract_address,
        selector: get_selector_from_name("increase_balance")?,
        calldata: vec![Felt::from_hex("0x50")?],
    };

    let call_contract_fn_result = account.execute_v3(vec![call]).send().await?;
    Ok(call_contract_fn_result)
}

pub async fn block_number(url: Url) -> Result<u64, OpenRpcTestGenError> {
    let rpc_client = JsonRpcClient::new(HttpTransport::new(url.clone()));

    match rpc_client.block_number().await {
        Ok(block_number) => Ok(block_number),
        Err(e) => Err(OpenRpcTestGenError::ProviderError(e)),
    }
}

pub async fn chain_id(url: Url) -> Result<Felt, OpenRpcTestGenError> {
    let rpc_client = JsonRpcClient::new(HttpTransport::new(url.clone()));

    match rpc_client.chain_id().await {
        Ok(chain_id) => Ok(chain_id),
        Err(e) => Err(OpenRpcTestGenError::ProviderError(e)),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn call(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<Vec<Felt>, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let declare_contract_hash = match account
        .declare_v2(Arc::new(flattened_sierra_class), compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };
    let deployment_hash = match declare_contract_hash {
        Ok(class_hash) => {
            let factory = ContractFactory::new(class_hash, account.clone());
            let mut salt_buffer = [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt_buffer[1..]);
            let result = factory
                .deploy_v1(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .max_fee(Felt::from_dec_str("100000000000000000")?)
                .send()
                .await?;
            wait_for_sent_transaction(result.transaction_hash, &user_passed_account).await?;
            Ok(result.transaction_hash)
        }
        Err(e) => Err(e),
    };

    let deployment_receipt = match deployment_hash {
        Ok(hash) => provider.get_transaction_receipt(hash).await?,
        Err(e) => {
            return Err(e);
        }
    };

    let contract_address = match deployment_receipt {
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

    let balance = provider
        .call(
            FunctionCall {
                calldata: vec![],
                contract_address,
                entry_point_selector: get_selector_from_name("get_balance")?,
            },
            BlockId::Tag(BlockTag::Pending),
        )
        .await?;

    Ok(balance)
}

#[allow(clippy::too_many_arguments)]
pub async fn estimate_message_fee(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<FeeEstimate<Felt>, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let declare_contract_hash = match account
        .declare_v2(Arc::new(flattened_sierra_class), compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };
    let deployment_hash = match declare_contract_hash {
        Ok(class_hash) => {
            let factory = ContractFactory::new(class_hash, account.clone());
            let mut salt_buffer = [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt_buffer[1..]);
            let result = factory
                .deploy_v1(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .max_fee(Felt::from_dec_str("100000000000000000")?)
                .send()
                .await?;
            wait_for_sent_transaction(result.transaction_hash, &user_passed_account).await?;
            Ok(result.transaction_hash)
        }
        Err(e) => Err(e),
    };

    let deployment_receipt = match deployment_hash {
        Ok(hash) => provider.get_transaction_receipt(hash).await?,
        Err(e) => {
            return Err(e);
        }
    };

    let contract_address = match deployment_receipt {
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

    let estimate = provider
        .estimate_message_fee(
            MsgFromL1 {
                from_address: String::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                to_address: contract_address,
                entry_point_selector: get_selector_from_name("deposit")?,
                payload: vec![(1_u32).into(), (10_u32).into()],
            },
            BlockId::Tag(BlockTag::Pending),
        )
        .await?;

    Ok(estimate)
}

pub async fn get_block_transaction_count(url: Url) -> Result<u64, OpenRpcTestGenError> {
    let client = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let count = client
        .get_block_transaction_count(BlockId::Tag(BlockTag::Latest))
        .await?;
    Ok(count)
}

pub async fn get_block_with_tx_hashes(
    url: Url,
) -> Result<BlockWithTxHashes<Felt>, OpenRpcTestGenError> {
    let client = JsonRpcClient::new(HttpTransport::new(url.clone()));

    let block = client
        .get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest))
        .await?;

    let response = match block {
        MaybePendingBlockWithTxHashes::Block(block) => block,
        _ => {
            return Err(OpenRpcTestGenError::Other(
                "unexpected block response type".to_string(),
            ));
        }
    };
    Ok(response)
}

pub async fn get_block_with_txs(url: Url) -> Result<BlockWithTxs<Felt>, OpenRpcTestGenError> {
    let client = JsonRpcClient::new(HttpTransport::new(url.clone()));

    let block = client
        .get_block_with_txs(BlockId::Tag(BlockTag::Latest))
        .await?;

    let block = match block {
        MaybePendingBlockWithTxs::Block(block) => block,
        _ => {
            return Err(OpenRpcTestGenError::Other(
                "unexpected block response type".to_string(),
            ));
        }
    };

    Ok(block)
}

pub async fn get_state_update(url: Url) -> Result<StateUpdate<Felt>, OpenRpcTestGenError> {
    let client = JsonRpcClient::new(HttpTransport::new(url.clone()));

    let state: MaybePendingStateUpdate<Felt> = client
        .get_state_update(BlockId::Tag(BlockTag::Latest))
        .await?;

    let state = match state {
        MaybePendingStateUpdate::Block(state) => state,
        _ => {
            return Err(OpenRpcTestGenError::Other(
                "unexpected block response type".to_string(),
            ));
        }
    };

    Ok(state)
}

pub async fn get_storage_at(
    url: Url,
    erc20_eth_contract_address: Option<Felt>,
) -> Result<Felt, OpenRpcTestGenError> {
    let client = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let erc20_eth_address = match erc20_eth_contract_address {
        Some(address) => address,
        None => Felt::from_hex("049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")?,
    };
    let key: Felt =
        Felt::from_hex("0000000000000000000000000000000000000000000000000000000000000001")?;
    // Checks L2 ETH balance via storage taking advantage of implementation detail
    let storage_value = client
        .get_storage_at(erc20_eth_address, key, BlockId::Tag(BlockTag::Latest))
        .await?;
    Ok(storage_value)
}

#[allow(clippy::too_many_arguments)]
pub async fn get_transaction_status_succeeded(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<TxnStatus, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let declare_contract_hash = match account
        .declare_v2(Arc::new(flattened_sierra_class), compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };
    let deployment_hash = match declare_contract_hash {
        Ok(class_hash) => {
            let factory = ContractFactory::new(class_hash, account.clone());
            let mut salt_buffer = [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt_buffer[1..]);
            let result = factory
                .deploy_v1(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .max_fee(Felt::from_dec_str("100000000000000000")?)
                .send()
                .await?;
            wait_for_sent_transaction(result.transaction_hash, &user_passed_account).await?;
            Ok(result.transaction_hash)
        }
        Err(e) => Err(e),
    };

    let deployment_receipt = match deployment_hash {
        Ok(hash) => provider.get_transaction_receipt(hash).await?,
        Err(e) => {
            return Err(e);
        }
    };

    let tx_hash = match deployment_receipt {
        TxnReceipt::Deploy(receipt) => receipt.common_receipt_properties.transaction_hash,
        TxnReceipt::Invoke(receipt) => receipt.common_receipt_properties.transaction_hash,
        _ => {
            return Err(OpenRpcTestGenError::CallError(
                CallError::UnexpectedReceiptType,
            ));
        }
    };

    let status = account.provider().get_transaction_status(tx_hash).await?;
    match status.finality_status {
        TxnStatus::AcceptedOnL2 => match status.execution_status {
            Some(TxnExecutionStatus::Succeeded) => Ok(TxnStatus::AcceptedOnL2),
            Some(TxnExecutionStatus::Reverted) => Err(OpenRpcTestGenError::TxnExecutionStatus(
                "Execution reverted".to_string(),
            )),
            None => Err(OpenRpcTestGenError::TxnExecutionStatus(
                "Execution status is None".to_string(),
            )),
        },
        _ => Err(OpenRpcTestGenError::Other(
            "unexpected transaction status".to_string(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn get_transaction_by_hash_invoke(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<InvokeTxnV1<Felt>, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let declare_contract_hash = match account
        .declare_v2(Arc::new(flattened_sierra_class), compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };

    let deployment_hash = match declare_contract_hash {
        Ok(class_hash) => {
            let factory = ContractFactory::new(class_hash, account.clone());
            let mut salt_buffer = [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt_buffer[1..]);

            let result = factory
                .deploy_v1(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .max_fee(Felt::from_dec_str("100000000000000000")?)
                .send()
                .await?;
            wait_for_sent_transaction(result.transaction_hash, &user_passed_account).await?;

            result.transaction_hash
        }
        Err(e) => {
            return Err(e);
        }
    };

    let txn = account
        .provider()
        .get_transaction_by_hash(deployment_hash)
        .await?;

    let txn = match txn {
        Txn::Invoke(InvokeTxn::V1(tx)) => tx,
        _ => {
            return Err(OpenRpcTestGenError::UnexpectedTxnType(
                "Unexpected txn type".to_string(),
            ));
        }
    };

    Ok(txn)
}

pub async fn get_transaction_by_hash_deploy_acc(
    url: Url,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<DeployAccountTxnV3<Felt>, OpenRpcTestGenError> {
    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let txn = provider
        .get_transaction_by_hash(deploy_account_txn_hash)
        .await?;

    let txn = match txn {
        Txn::DeployAccount(DeployAccountTxn::V3(tx)) => tx,
        _ => {
            return Err(OpenRpcTestGenError::UnexpectedTxnType(
                "Unexpected txn type".to_string(),
            ));
        }
    };

    Ok(txn)
}

pub async fn get_transaction_by_block_id_and_index(
    url: Url,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<Txn<Felt>, OpenRpcTestGenError> {
    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let block = provider.block_hash_and_number().await?;

    let block_txn_count = provider
        .get_block_transaction_count(BlockId::Hash(block.block_hash))
        .await?;

    let txn = provider
        .get_transaction_by_block_id_and_index(BlockId::Hash(block.block_hash), block_txn_count - 1)
        .await?;

    let txn = match txn {
        Txn::Invoke(InvokeTxn::V0(txn)) => Txn::Invoke(InvokeTxn::V0(txn)),
        Txn::Invoke(InvokeTxn::V1(txn)) => Txn::Invoke(InvokeTxn::V1(txn)),
        Txn::Invoke(InvokeTxn::V3(txn)) => Txn::Invoke(InvokeTxn::V3(txn)),
        Txn::Declare(DeclareTxn::V0(txn)) => Txn::Declare(DeclareTxn::V0(txn)),
        Txn::Declare(DeclareTxn::V1(txn)) => Txn::Declare(DeclareTxn::V1(txn)),
        Txn::Declare(DeclareTxn::V2(txn)) => Txn::Declare(DeclareTxn::V2(txn)),
        Txn::Declare(DeclareTxn::V3(txn)) => Txn::Declare(DeclareTxn::V3(txn)),
        Txn::DeployAccount(DeployAccountTxn::V1(txn)) => {
            Txn::DeployAccount(DeployAccountTxn::V1(txn))
        }
        Txn::DeployAccount(DeployAccountTxn::V3(txn)) => {
            Txn::DeployAccount(DeployAccountTxn::V3(txn))
        }
        Txn::Deploy(DeployTxn {
            class_hash,
            constructor_calldata,
            contract_address_salt,
            version,
        }) => Txn::Deploy(DeployTxn {
            class_hash,
            constructor_calldata,
            contract_address_salt,
            version,
        }),
        _ => {
            let error_message = format!("Unexpected transaction response type: {:?}", txn);
            return Err(OpenRpcTestGenError::UnexpectedTxnType(error_message));
        }
    };

    Ok(txn)
}

pub async fn get_transaction_by_hash_non_existent_tx(url: Url) -> Result<(), OpenRpcTestGenError> {
    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));

    let err = provider
        .get_transaction_by_hash(Felt::from_hex("0xdeafbeefdeadbeef")?)
        .await;

    match err {
        Err(ProviderError::StarknetError(StarknetError::TransactionHashNotFound)) => Ok(()),
        Err(e) => Err(OpenRpcTestGenError::ProviderError(e)),
        Ok(_) => Err(OpenRpcTestGenError::Other(
            "Transaction unexpectedly found".to_string(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn get_transaction_receipt(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<InvokeTxnReceipt<Felt>, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let declare_contract_hash = match account
        .declare_v3(flattened_sierra_class, compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };

    let deployment_hash = match declare_contract_hash {
        Ok(class_hash) => {
            let factory = ContractFactory::new(class_hash, account.clone());
            let mut salt_buffer = [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt_buffer[1..]);

            let result = factory
                .deploy_v3(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .send()
                .await?;
            wait_for_sent_transaction(result.transaction_hash, &user_passed_account).await?;
            Ok(result.transaction_hash)
        }
        Err(e) => Err(e),
    };

    let deployment_receipt = match deployment_hash {
        Ok(hash) => provider.get_transaction_receipt(hash).await?,
        Err(e) => {
            return Err(e);
        }
    };

    let contract_address = match deployment_receipt {
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

    let call = Call {
        to: contract_address,
        selector: get_selector_from_name("increase_balance")?,
        calldata: vec![Felt::from_hex("0x50")?],
    };

    let result = account.execute_v3(vec![call]).send().await?;
    wait_for_sent_transaction(result.transaction_hash, &user_passed_account).await?;

    let receipt = provider
        .get_transaction_receipt(result.transaction_hash)
        .await?;

    match receipt {
        TxnReceipt::Invoke(receipt) => Ok(receipt),
        _ => Err(OpenRpcTestGenError::CallError(
            CallError::UnexpectedReceiptType,
        )),
    }
}

// #[allow(dead_code)]
// pub async fn get_transaction_receipt_revert(
//     url: Url,
//     sierra_path: &str,
//     casm_path: &str,
//     account_class_hash: Option<Felt>,
//     account_address: Option<Felt>,
//     private_key: Option<Felt>,
//     erc20_strk_contract_address: Option<Felt>,
//     erc20_eth_contract_address: Option<Felt>,
//     amount_per_test: Option<Felt>,
// ) -> Result<(), OpenRpcTestGenError> {
//     let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
//     let create_acc_data =
//         match create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await {
//             Ok(value) => value,
//             Err(e) => {
//                 info!("{}", "Could not create an account");
//                 return Err(e.into());
//             }
//         };

//     let (
//         account_address,
//         private_key,
//         erc20_strk_contract_address,
//         erc20_eth_contract_address,
//         amount_per_test,
//     ) = validate_inputs(
//         account_address,
//         private_key,
//         erc20_strk_contract_address,
//         erc20_eth_contract_address,
//         amount_per_test,
//     )?;

//     let chain_id = get_chain_id(&provider).await?;

//     let user_passed_account = SingleOwnerAccount::new(
//         provider.clone(),
//         LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
//         account_address,
//         chain_id,
//         ExecutionEncoding::New,
//     );

//     setup_generated_account(
//         user_passed_account,
//         erc20_eth_contract_address,
//         erc20_strk_contract_address,
//         amount_per_test,
//         create_acc_data.address,
//     )
//     .await?;

//     let wait_config = WaitForTx {
//         wait: true,
//         wait_params: ValidatedWaitParams::default(),
//     };

//     match deploy_account(&provider, chain_id, wait_config, create_acc_data,DeployAccountVersion::V3).await {
//         Ok(value) => Some(value),
//         Err(e) => {
//             info!("{}", "Could not deploy an account");
//             return Err(e.into());
//         }
//     };

//     let sender_address = create_acc_data.address;
//     let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

//     let mut account = SingleOwnerAccount::new(
//         provider.clone(),
//         signer,
//         sender_address,
//         chain_id,
//         ExecutionEncoding::New,
//     );

//     account.set_block_id(BlockId::Tag(BlockTag::Pending));
//     let transfer_execution = account
//         .execute_v1(vec![Call {
//             to: erc20_eth_contract_address,
//             selector: get_selector_from_name("transfer")?,
//             calldata: vec![account_address, amount_per_test, Felt::ZERO],
//         }])
//         .send()
//         .await
//         .unwrap();
//     info!("ok");

//     let receipt = account
//         .provider()
//         .get_transaction_receipt(transfer_execution.transaction_hash)
//         .await
//         .unwrap();

//     match receipt {
//         TxnReceipt::Invoke(invoke_receipt) => match invoke_receipt.common_receipt_properties.anon {
//             Anonymous::Reverted(_) => {
//                 info!("reverted");
//                 Ok(())
//             }
//             Anonymous::Successful(_) => {
//                 info!("successful");
//                 Err(OpenRpcTestGenError::CallError(CallError::UnexpectedExecutionResult))
//             }
//             _ => {
//                 info!("other");
//                 Err(OpenRpcTestGenError::CallError(CallError::UnexpectedExecutionResult))
//             }
//         },
//         _ => {
//             info!("Unexpected response type TxnReceipt: {:?}", receipt);
//             Err(OpenRpcTestGenError::CallError(CallError::UnexpectedReceiptType))
//         }
//     }
// }

#[allow(clippy::too_many_arguments)]
pub async fn get_class(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<ContractClass<Felt>, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let declare_contract_hash = match account
        .declare_v2(Arc::new(flattened_sierra_class), compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };

    let contract_class = account
        .provider()
        .get_class(BlockId::Tag(BlockTag::Latest), declare_contract_hash?)
        .await?;

    Ok(contract_class)
}

#[allow(clippy::too_many_arguments)]
pub async fn get_class_hash_at(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<Felt, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let declare_contract_hash = match account
        .declare_v2(Arc::new(flattened_sierra_class), compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };
    let deployment_hash = match declare_contract_hash {
        Ok(class_hash) => {
            let factory = ContractFactory::new(class_hash, account.clone());
            let mut salt_buffer = [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt_buffer[1..]);
            let result = factory
                .deploy_v1(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .max_fee(Felt::from_dec_str("100000000000000000")?)
                .send()
                .await?;
            wait_for_sent_transaction(result.transaction_hash, &user_passed_account).await?;
            Ok(result.transaction_hash)
        }
        Err(e) => Err(e),
    };

    let deployment_receipt = match deployment_hash {
        Ok(hash) => provider.get_transaction_receipt(hash).await?,
        Err(e) => {
            return Err(e);
        }
    };

    let contract_address = match deployment_receipt {
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
    let contract_class_hash = account
        .provider()
        .get_class_hash_at(BlockId::Tag(BlockTag::Pending), contract_address)
        .await?;

    Ok(contract_class_hash)
}

#[allow(clippy::too_many_arguments)]
pub async fn get_class_at(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    account_class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<ContractClass<Felt>, OpenRpcTestGenError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await?;

    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        create_account(&provider, AccountType::Oz, Option::None, account_class_hash).await?;

    let (
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    ) = validate_inputs(
        account_address,
        private_key,
        erc20_strk_contract_address,
        erc20_eth_contract_address,
        amount_per_test,
    )?;

    let chain_id = get_chain_id(&provider).await?;

    let user_passed_account = SingleOwnerAccount::new(
        provider.clone(),
        LocalWallet::from(SigningKey::from_secret_scalar(private_key)),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );

    setup_generated_account(
        user_passed_account.clone(),
        erc20_eth_contract_address,
        erc20_strk_contract_address,
        amount_per_test,
        create_acc_data.address,
    )
    .await?;

    let wait_config = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let deploy_account_txn_hash = deploy_account(
        &provider,
        chain_id,
        wait_config,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await?;

    wait_for_sent_transaction(deploy_account_txn_hash, &user_passed_account).await?;

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let declare_contract_hash = match account
        .declare_v2(Arc::new(flattened_sierra_class), compiled_class_hash)
        .send()
        .await
    {
        Ok(result) => Ok(result.class_hash),
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
            Ok(extract_class_hash_from_error(&full_error_message)?)
        }
    };
    let deployment_hash = match declare_contract_hash {
        Ok(class_hash) => {
            let factory = ContractFactory::new(class_hash, account.clone());
            let mut salt_buffer = [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt_buffer[1..]);
            let result = factory
                .deploy_v1(vec![], Felt::from_bytes_be(&salt_buffer), true)
                .max_fee(Felt::from_dec_str("100000000000000000")?)
                .send()
                .await?;
            wait_for_sent_transaction(result.transaction_hash, &user_passed_account).await?;
            Ok(result.transaction_hash)
        }
        Err(e) => Err(e),
    };

    let deployment_receipt = match deployment_hash {
        Ok(hash) => provider.get_transaction_receipt(hash).await?,
        Err(e) => {
            return Err(e);
        }
    };

    let contract_address = match deployment_receipt {
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

    let contract_class = account
        .provider()
        .get_class_at(BlockId::Tag(BlockTag::Pending), contract_address)
        .await?;

    Ok(contract_class)
}
