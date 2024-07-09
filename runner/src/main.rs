mod args;

use args::Args;
use clap::Parser;

use shared::account_balance::Version;
use v0_0_5::endpoints::{
    account_balance::account_balance, add_declare_transaction::add_declare_transaction,
    block_number::block_number, call::call, get_block_with_tx_hashes::get_block_with_tx_hashes,
    get_block_with_tx_receipts::get_block_with_receipts, get_block_with_txs::get_block_with_txs,
    get_nonce::get_nonce, get_transaction_by_hash_invoke_v1::get_transaction_by_hash_invoke_v1,
    get_transaction_status_succeded::get_transaction_status_succeeded, specversion::specversion,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let args = Args::parse();
    let (url, chain_id, vers) = (args.url.clone(), args.chain_id.clone(), args.vers);
    match vers {
        Version::V0_0_5 => {
            match account_balance(url.clone()).await {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("{}", e);
                    return Ok(());
                }
            };

            match specversion(url.clone()).await {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("{}", e);
                    return Ok(());
                }
            };

            match get_nonce(url.clone(), chain_id.clone()).await {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("{}", e);
                    return Ok(());
                }
            };

            match get_block_with_tx_hashes(url.clone()).await {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("{}", e);
                    return Ok(());
                }
            };

            // match get_block_with_txs(url.clone()).await {
            //     Ok(_) => {}
            //     Err(e) => {
            //         eprintln!("{}", e);
            //         return Ok(());
            //     }
            // }

            match get_transaction_status_succeeded(url.clone(), chain_id.clone()).await {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("{}", e);
                    return Ok(());
                }
            }

            // match get_block_with_receipts(url.clone()).await {
            //     Ok(_) => {}
            //     Err(e) => {
            //         eprintln!("{}", e);
            //         return Ok(());
            //     }
            // }
            // match get_transaction_by_hash_invoke_v1(url.clone()).await {
            //     Ok(_) => {}
            //     Err(e) => {
            //         eprintln!("{}", e);
            //         return Ok(());
            //     }
            // }

            // match block_number(url.clone()).await {
            //     Ok(_) => {}
            //     Err(e) => {
            //         eprintln!("{}", e);
            //         return Ok(());
            //     }
            // };
            // match add_declare_transaction(url.clone(), chain_id.clone()).await {
            //     Ok(_) => {}
            //     Err(e) => {
            //         eprintln!("{}", e);
            //         return Ok(());
            //     }
            // };

            // match call(url.clone(), chain_id.clone()).await {
            //     Ok(_) => {}
            //     Err(e) => {
            //         eprintln!("{}", e);
            //         return Ok(());
            //     }
            // };
        }
        Version::V0_0_6 => {}
    }

    // run(args.url.clone()).await;

    // create_mint_deploy(Url::parse(args.url.as_ref())?).await?;

    // let client = DevnetClient::new(HttpTransport::new(Url::parse(args.url.as_ref())?));

    // First of all create and deploy an account:
    // let account_create_response = create_mint_deploy(args.url.clone()).await?;
    // info!("{:?}", account_create_response.account_data);
    // let signer = LocalWallet::from(SigningKey::from_secret_scalar(FieldElement::from_hex_be()));

    // let account = SingleOwnerAccount::new(
    //     client,

    //     account_create_response.account_data.address,
    //     Felt::from_hex(&args.chain_id).unwrap(),
    //     ExecutionEncoding::New
    // )

    // let account = SingleOwnerAccount::new(
    //     client,
    //     LocalWallet::from(SigningKey::from_secret_scalar(
    //         account_create_response.account_data.private_key,
    //     )),
    //     account_create_response.account_data.address,
    //     FieldElement::from_hex_be(&args.chain_id).unwrap(),
    //     ExecutionEncoding::New,
    // );

    // let account = SingleOwnerAccount::new(
    //     client,
    //     LocalWallet::from(SigningKey::from_secret_scalar(args.private_key)),
    //     args.account_address,
    //     FieldElement::from_hex_be(&args.chain_id).unwrap(),
    //     ExecutionEncoding::New,
    // );

    // match account.provider().get_predeployed_accounts().await {
    //     Ok(value) => {
    //         info!("{}", "Get predeployed accounts COMPATIBLE".green());
    //         println!("{:?}", value);
    //     }
    //     Err(_) => info!("{}", "INCOMPATIBLE".red()),
    // }
    // match account.provider().get_config().await {
    //     Ok(value) => {
    //         info!("{}", "Get config COMPATIBLE".green());
    //         println!("{:?}", value);
    //     }
    //     Err(_) => info!("{}", "INCOMPATIBLE".red()),
    // }

    // match account
    //     .provider()
    //     .get_account_balance(
    //         account_create_response.account_data.address,
    //         FeeUnit::WEI,
    //         BlockTag::Latest,
    //     )
    //     .await
    // {
    //     Ok(value) => {
    //         info!("{}", "get account balance COMPATIBLE".green());
    //         println!("{:?}", value);
    //     }
    //     Err(_) => info!("{}", "INCOMPATIBLE".red()),
    // }
    // match account
    //     .provider()
    //     .mint(account_create_response.account_data.address, 1000)
    //     .await
    // {
    //     Ok(value) => {
    //         info!("{}", "COMPATIBLE".green());
    //         println!("{:?}", value);
    //     }
    //     Err(_) => info!("{}", "INCOMPATIBLE".red()),
    // }
    // match account.provider().set_time(100, false).await {
    //     Ok(value) => {
    //         info!("{}", "COMPATIBLE".green());
    //         println!("{:?}", value);
    //     }
    //     Err(_) => info!("{}", "INCOMPATIBLE".red()),
    // }

    // match account.provider().increase_time(1000).await {
    //     Ok(value) => {
    //         info!("{}", "COMPATIBLE".green());
    //         println!("{:?}", value);
    //     }
    //     Err(_) => info!("{}", "INCOMPATIBLE".red()),
    // }

    // match account.provider().create_block().await {
    //     Ok(value) => {
    //         info!("{}", "COMPATIBLE".green());
    //         if let Some(block_hash) = value.get("block_hash").and_then(|v| v.as_str()) {
    //             println!("Block hash: {}", block_hash);
    //             match account
    //                 .provider()
    //                 .abort_blocks(block_hash.to_string())
    //                 .await
    //             {
    //                 Ok(value) => {
    //                     info!("{}", "COMPATIBLE".green());
    //                     println!("{:?}", value);
    //                 }
    //                 Err(_) => info!("{}", "INCOMPATIBLE".red()),
    //             }
    //         } else {
    //             println!("Block hash not found");
    //         }
    //     }
    //     Err(_) => info!("{}", "INCOMPATIBLE".red()),
    // }

    Ok(())
}

// async fn fuzzy_test_mint(
//     account: &SingleOwnerAccount<DevnetClient<HttpTransport>, LocalWallet>,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let mut rng = rand::thread_rng();
//     let test_count = rng.gen_range(5..=20);

//     for _ in 0..test_count {
//         let initial_balance = account
//             .provider()
//             .get_account_balance(account.address(), FeeUnit::WEI, BlockTag::Latest)
//             .await?;

//         let mint_amount = rng.gen_range(u128::MIN + 1..=u128::MAX);

//         let mint_result = account
//             .provider()
//             .mint(account.address(), mint_amount)
//             .await?;

//         let new_balance = account
//             .provider()
//             .get_account_balance(account.address(), FeeUnit::WEI, BlockTag::Latest)
//             .await?;
//     }

//     Ok(())
// }
