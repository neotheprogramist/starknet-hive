use std::path::PathBuf;
use std::sync::Arc;

use crate::utils::v7::accounts::account::{Account, AccountError};
use crate::utils::v7::contract::{self, HashAndFlatten};
use crate::utils::v7::providers::provider::ProviderError;
use crate::utils::v7::{
    accounts::single_owner::SingleOwnerAccount,
    contract::{CompiledClass, SierraClass},
    providers::provider::Provider,
    signers::local_wallet::LocalWallet,
};

use std::fs::File;

use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use cairo_lang_starknet_classes::contract_class::ContractClass as CairoContractClass;

use regex::Regex;
use starknet_types_core::felt::Felt;
use starknet_types_rpc::v0_7_1::{ContractClass, TxnHash};

use thiserror::Error;
use tokio::io::AsyncReadExt;
use tracing::{debug, info};
use url::ParseError;

pub async fn declare_contract<P: Provider + Send + Sync>(
    account: &SingleOwnerAccount<P, LocalWallet>,
    sierra_path: PathBuf,
    casm_path: PathBuf,
) -> Result<Felt, RunnerError> {
    let (flattened_sierra_class, compiled_class_hash) =
        get_compiled_contract(sierra_path, casm_path).await.unwrap();

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
                Err(RunnerError::AccountFailure(format!(
                    "Transaction execution error: {}",
                    sign_error
                )))
            }
        }

        Err(AccountError::Provider(ProviderError::Other(starkneterror))) => {
            if starkneterror.to_string().contains("is already declared") {
                Ok(parse_class_hash_from_error(&starkneterror.to_string())?)
            } else {
                Err(RunnerError::AccountFailure(format!(
                    "Transaction execution error: {}",
                    starkneterror
                )))
            }
        }
        Err(e) => {
            info!("General account error encountered: {:?}, possible cause - incorrect address or public_key in environment variables!", e);
            Err(RunnerError::AccountFailure(format!("Account error: {}", e)))
        }
    }
}

pub fn parse_class_hash_from_error(error_msg: &str) -> Result<Felt, RunnerError> {
    debug!("Error message: {}", error_msg);
    let re = Regex::new(r#"StarkFelt\("(0x[a-fA-F0-9]+)"\)"#)?;

    if let Some(captures) = re.captures(error_msg) {
        if let Some(contract_address) = captures.get(1) {
            match Felt::from_hex(contract_address.as_str()) {
                Ok(felt) => Ok(felt),
                Err(_) => Err(RunnerError::ClassHash(
                    ClassHashParseError::InvalidClassHash,
                )),
            }
        } else {
            Err(RunnerError::ClassHash(
                ClassHashParseError::NoClassHashFound,
            ))
        }
    } else {
        Err(RunnerError::ClassHash(
            ClassHashParseError::NoClassHashFound,
        ))
    }
}

pub fn extract_class_hash_from_error(error_msg: &str) -> Result<Felt, RunnerError> {
    let re = Regex::new(r#"0x[a-fA-F0-9]{63,64}"#)?;

    if let Some(capture) = re.find(error_msg) {
        match Felt::from_hex(capture.as_str()) {
            Ok(felt) => Ok(felt),
            Err(_) => Err(RunnerError::ClassHash(
                ClassHashParseError::InvalidClassHash,
            )),
        }
    } else {
        Err(RunnerError::ClassHash(
            ClassHashParseError::NoClassHashFound,
        ))
    }
}

pub async fn get_compiled_contract(
    sierra_path: PathBuf,
    casm_path: PathBuf,
) -> Result<(ContractClass<Felt>, TxnHash<Felt>), RunnerError> {
    let mut file = tokio::fs::File::open(&sierra_path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RunnerError::ReadFileError(
                "Contract json file not found, please execute scarb build command".to_string(),
            )
        } else {
            RunnerError::ReadFileError(e.to_string())
        }
    })?;

    let mut sierra = String::new();
    file.read_to_string(&mut sierra)
        .await
        .map_err(|e| RunnerError::ReadFileError(e.to_string()))?;

    let mut file = tokio::fs::File::open(&casm_path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RunnerError::ReadFileError(
                "Contract json file not found, please execute scarb build command".to_string(),
            )
        } else {
            RunnerError::ReadFileError(e.to_string())
        }
    })?;
    let mut casm = String::new();
    file.read_to_string(&mut casm)
        .await
        .map_err(|e| RunnerError::ReadFileError(e.to_string()))?;

    let contract_artifact: SierraClass = serde_json::from_str(&sierra)?;
    let compiled_class: CompiledClass = serde_json::from_str(&casm)?;

    let casm_class_hash = compiled_class.class_hash()?;
    let flattened_class = contract_artifact.clone().flatten()?;

    Ok((flattened_class, casm_class_hash))
}

pub async fn get_compiled_contract_string(
    sierra_path: PathBuf,
    casm_path: PathBuf,
) -> Result<(String, String), RunnerError> {
    let mut file = tokio::fs::File::open(&sierra_path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RunnerError::ReadFileError(
                "Contract json file not found, please execute scarb build command".to_string(),
            )
        } else {
            RunnerError::ReadFileError(e.to_string())
        }
    })?;

    let mut sierra = String::new();
    file.read_to_string(&mut sierra)
        .await
        .map_err(|e| RunnerError::ReadFileError(e.to_string()))?;

    let mut file = tokio::fs::File::open(&casm_path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RunnerError::ReadFileError(
                "Contract json file not found, please execute scarb build command".to_string(),
            )
        } else {
            RunnerError::ReadFileError(e.to_string())
        }
    })?;
    let mut casm = String::new();
    file.read_to_string(&mut casm)
        .await
        .map_err(|e| RunnerError::ReadFileError(e.to_string()))?;

    Ok((sierra, casm))
}

pub async fn get_compiled_contract_from_string(
    sierra: String,
    casm: String,
) -> Result<(ContractClass<Felt>, TxnHash<Felt>), RunnerError> {
    let contract_artifact: SierraClass = serde_json::from_str(&sierra)?;
    let compiled_class: CompiledClass = serde_json::from_str(&casm)?;

    let casm_class_hash = compiled_class.class_hash()?;
    let flattened_class = contract_artifact.clone().flatten()?;

    Ok((flattened_class, casm_class_hash))
}

pub fn prepare_contract_declaration_params(
    artifact_path: &PathBuf,
) -> Result<(ContractClass<Felt>, Felt), RunnerError> {
    let flattened_class = get_flattened_class(artifact_path)?;
    let compiled_class_hash = get_compiled_class_hash(artifact_path)?;
    Ok((flattened_class, compiled_class_hash))
}

fn get_flattened_class(artifact_path: &PathBuf) -> Result<ContractClass<Felt>, RunnerError> {
    let file = File::open(artifact_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RunnerError::ReadFileError("Artifact path not found".to_string())
        } else {
            RunnerError::ReadFileError(e.to_string())
        }
    })?;
    let contract_artifact: SierraClass = serde_json::from_reader(&file)?;
    Ok(contract_artifact.clone().flatten()?)
}

fn get_compiled_class_hash(artifact_path: &PathBuf) -> Result<Felt, RunnerError> {
    let file = File::open(artifact_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RunnerError::ReadFileError("Artifact path not found".to_string())
        } else {
            RunnerError::ReadFileError(e.to_string())
        }
    })?;

    let casm_contract_class: CairoContractClass = serde_json::from_reader(file)?;
    let casm_contract =
        CasmContractClass::from_contract_class(casm_contract_class, true, usize::MAX)?;
    let res = serde_json::to_string_pretty(&casm_contract)?;
    let compiled_class: CompiledClass = serde_json::from_str(&res)?;
    Ok(compiled_class.class_hash()?)
}

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error(transparent)]
    ParsingError(#[from] ParseError),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),

    #[error("ReadFileError error: {0}")]
    ReadFileError(String),

    #[error("Account error: {0}")]
    AccountFailure(String),

    #[error("Deployment error: {0}")]
    DeploymentFailure(String),

    #[error(transparent)]
    BoxError(#[from] Box<dyn std::error::Error>),

    #[error("Starknet-devnet not launched : {0}")]
    DevnetNotLaunched(String),

    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error(transparent)]
    ClassHash(#[from] ClassHashParseError),

    #[error(transparent)]
    Regex(#[from] regex::Error),

    #[error(transparent)]
    JsonError(#[from] contract::JsonError),

    #[error(transparent)]
    ComputeClassHashError(#[from] contract::ComputeClassHashError),

    #[error(transparent)]
    StarknetSierraCompilationError(
        #[from] cairo_lang_starknet_classes::casm_contract_class::StarknetSierraCompilationError,
    ),
}

#[derive(Debug, Error)]
pub enum ClassHashParseError {
    #[error("Failed to parse class hash from error message")]
    InvalidClassHash,

    #[error("No class hash found in error message")]
    NoClassHashFound,
}
