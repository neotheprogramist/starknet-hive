use serde::Serialize;

use starknet_devnet_types::rpc::transactions::BroadcastedTransaction;
use std::error::Error;
use std::fs;
use std::{fs::File, io::BufReader};
use tracing::{error, info};

use crate::starknet::state::add_declare_transaction::add_declare_transaction;
use crate::starknet::state::add_deploy_account_transaction::add_deploy_account_transaction;
use crate::starknet::state::add_invoke_transaction::add_invoke_transaction;
use crate::starknet::state::Starknet;

pub fn read_transactions_file(
    file_path: &str,
) -> Result<Vec<BroadcastedTransaction>, Box<dyn Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let transactions: Vec<BroadcastedTransaction> = serde_json::from_reader(reader)?;
    Ok(transactions)
}

pub fn handle_transactions(starknet: &mut Starknet, transactions: Vec<BroadcastedTransaction>) {
    for (index, transaction) in transactions.into_iter().enumerate() {
        match transaction {
            BroadcastedTransaction::Invoke(tx) => match add_invoke_transaction(starknet, tx) {
                Err(e) => {
                    tracing::error!(
                        "Error processing Invoke transaction at index {}: {:?}",
                        index,
                        e
                    );
                }
                Ok(_) => {
                    tracing::info!(
                        "Successfully processed Invoke transaction at index {}",
                        index
                    );
                }
            },
            BroadcastedTransaction::Declare(tx) => match add_declare_transaction(starknet, tx) {
                Err(e) => {
                    tracing::error!(
                        "Error processing Declare transaction at index {}: {:?}",
                        index,
                        e
                    );
                }
                Ok(_) => {
                    tracing::info!(
                        "Successfully processed Declare transaction at index {}",
                        index
                    );
                }
            },
            BroadcastedTransaction::DeployAccount(tx) => {
                match add_deploy_account_transaction(starknet, tx) {
                    Err(e) => {
                        tracing::error!(
                            "Error processing DeployAccount transaction at index {}: {:?}",
                            index,
                            e
                        );
                    }
                    Ok(_) => {
                        tracing::info!(
                            "Successfully processed DeployAccount transaction at index {}",
                            index
                        );
                    }
                }
            }
        }
    }
}

pub fn write_result_state_file<T: Serialize>(
    file_path: &str,
    data: &T,
) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = std::path::Path::new(file_path).parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(file_path)?;
    serde_json::to_writer_pretty(&file, data).map_err(|e| {
        error!("Failed to write JSON to file: {}", e);
        e
    })?;

    info!("State written into {}", file_path);
    Ok(())
}
