use std::path::PathBuf;

use starknet_types_rpc::{
    v0_7_1::{BlockId, BlockTag},
    PriceUnit,
};

use url::Url;

use crate::utils::v7::{
    accounts::{
        creation::{
            create::{create_account, AccountType},
            helpers::get_chain_id,
            structs::MintRequest2,
        },
        deployment::{
            deploy::{deploy_account, DeployAccountVersion},
            structs::{ValidatedWaitParams, WaitForTx},
        },
        single_owner::{ExecutionEncoding, SingleOwnerAccount},
        utils::mint::mint,
    },
    endpoints::{declare_contract::declare_contract, deploy_contract::deploy_contract},
    providers::jsonrpc::{HttpTransport, JsonRpcClient},
    signers::local_wallet::LocalWallet,
};

pub async fn decalare_and_deploy(
    url: Url,
    sierra_path: PathBuf,
    casm_path: PathBuf,
) -> Result<(), String> {
    let provider = JsonRpcClient::new(HttpTransport::new(url.clone()));
    let create_acc_data =
        match create_account(&provider, AccountType::Oz, Option::None, Option::None).await {
            Ok(value) => value,
            Err(e) => {
                return Err(e.to_string());
            }
        };

    match mint(
        url.clone(),
        &MintRequest2 {
            amount: u128::MAX,
            address: create_acc_data.address,
            unit: PriceUnit::Fri,
        },
    )
    .await
    {
        Ok(_) => {}
        Err(e) => {
            return Err(e.to_string());
        }
    };

    let wait_conifg = WaitForTx {
        wait: true,
        wait_params: ValidatedWaitParams::default(),
    };

    let chain_id = get_chain_id(&provider).await.unwrap();

    match deploy_account(
        &provider,
        chain_id,
        wait_conifg,
        create_acc_data,
        DeployAccountVersion::V3,
    )
    .await
    {
        Ok(value) => Some(value),
        Err(e) => {
            return Err(e.to_string());
        }
    };

    let sender_address = create_acc_data.address;
    let signer: LocalWallet = LocalWallet::from(create_acc_data.signing_key);

    let mut account = SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(url.clone())),
        signer,
        sender_address,
        chain_id,
        ExecutionEncoding::New,
    );
    account.set_block_id(BlockId::Tag(BlockTag::Latest));

    let class_hash = declare_contract(&account, sierra_path, casm_path)
        .await
        .unwrap();

    deploy_contract(&account, class_hash).await;

    Ok(())
}
