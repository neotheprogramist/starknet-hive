use super::declare_contract::RunnerError;
use crate::{
    macros::macros_errors::AssertionNoPanicError,
    utils::{
        conversions::errors::ConversionsError,
        v7::{
            accounts::{
                account::AccountError, errors::CreationError,
                single_owner::SignError as SingleOwnerSignError, utils::mint::MintError,
            },
            providers::provider::ProviderError,
            signers::local_wallet::SignError,
        },
        v8::types::ProofError,
    },
};
use core::fmt::{Display, Formatter, Result};
use starknet_types_core::felt::FromStrError;
use std::{collections::HashMap, convert::Infallible, num::ParseIntError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OpenRpcTestGenError {
    #[error(transparent)]
    RequestError(#[from] reqwest::Error),
    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),
    #[error(transparent)]
    RunnerError(#[from] RunnerError),
    #[error(transparent)]
    CreationError(#[from] CreationError),
    #[error(transparent)]
    ContinuationTokenError(#[from] ContinuationTokenError),
    #[error(transparent)]
    MintError(#[from] MintError),
    #[error(transparent)]
    SignError(#[from] SignError),
    #[error(transparent)]
    GetPublicKeyError(#[from] crate::utils::v7::signers::local_wallet::Infallible),
    #[error(transparent)]
    AccountError_(
        #[from] AccountError<crate::utils::v7::accounts::single_owner::SignError<SignError>>,
    ),
    #[error(transparent)]
    SingleOwnerSignError(#[from] SingleOwnerSignError<SignError>),
    #[error(transparent)]
    AccountError(#[from] AccountError<SignError>),
    #[error(transparent)]
    AccountFactoryError(
        #[from] crate::utils::v7::accounts::factory::AccountFactoryError<SignError>,
    ),
    #[error(transparent)]
    ProviderError(#[from] ProviderError),
    #[error(transparent)]
    CallError(#[from] CallError),
    #[error(transparent)]
    NonAsciiNameError(#[from] NonAsciiNameError),
    #[error(transparent)]
    FromStrError(#[from] FromStrError),
    #[error(transparent)]
    Infallible(#[from] Infallible),
    #[error(transparent)]
    AssertNoPanic(#[from] AssertionNoPanicError),
    #[error(transparent)]
    Conversions(#[from] ConversionsError),
    #[error(transparent)]
    JoinError(#[from] tokio::task::JoinError),
    #[error(transparent)]
    EcdsaSignError(#[from] starknet::core::crypto::EcdsaSignError),
    #[error("Unexpected block type {0}")]
    UnexpectedBlockResponseType(String),
    #[error("Unexpected txn type {0}")]
    UnexpectedTxnType(String),
    #[error("TxnExecutionStatus reverted {0}")]
    TxnExecutionStatus(String),
    #[error("Required input not provided {0}")]
    InvalidInput(String),
    #[error("Timeout waiting for tx receipt {0}")]
    Timeout(String),
    #[error("Txn rejected {0}")]
    TransactionRejected(String),
    #[error("Txn failed {0}")]
    TransactionFailed(String),
    #[error("Empty url error {0}")]
    EmptyUrlList(String),
    #[error("Transaction with hash {0} not found in the block")]
    TransactionNotFound(String),
    #[error(transparent)]
    T9nError(#[from] t9n::txn_validation::errors::Error),
    #[error("Transaction index overflowed when converting to u64")]
    TransactionIndexOverflow,
    #[error("Unexpected error occured: {0}")]
    Other(String),
    #[error("One or more tests failed: {failed_tests:?}")]
    TestSuiteFailure {
        failed_tests: HashMap<String, String>,
    },
    #[error(transparent)]
    Proof(#[from] ProofError),
}

#[derive(PartialEq, Eq, Debug, Error)]
pub enum ContinuationTokenError {
    #[error("Invalid data")]
    InvalidToken,
    #[error(transparent)]
    ParseFailed(#[from] ParseIntError),
}

#[derive(Error, Debug)]
pub enum CallError {
    #[error("Error creating an account")]
    CreateAccountError(String),

    #[error(transparent)]
    ProviderError(#[from] ProviderError),

    #[error(transparent)]
    FromStrError(#[from] FromStrError),

    #[error(transparent)]
    RunnerError(#[from] RunnerError),

    #[error("Unexpected receipt response type")]
    UnexpectedReceiptType,

    #[error("Unexpected execution result")]
    UnexpectedExecutionResult,
}

#[derive(Debug)]
pub struct NonAsciiNameError;

impl std::error::Error for NonAsciiNameError {}

impl Display for NonAsciiNameError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "the provided name contains non-ASCII characters")
    }
}
