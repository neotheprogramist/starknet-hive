use starknet_types_core::felt::Felt;
use thiserror::Error;

use crate::utils::v7::providers::provider::ProviderError;

#[derive(Debug, thiserror::Error)]
#[error("Not all fields are prepared")]
pub struct NotPreparedError;
#[derive(Debug)]
pub enum ComputeClassHashError {
    InvalidBuiltinName,
    BytecodeSegmentLengthMismatch(BytecodeSegmentLengthMismatchError),
    InvalidBytecodeSegment(InvalidBytecodeSegmentError),
    PcOutOfRange(PcOutOfRangeError),
    Json(JsonError),
}
#[derive(Debug)]
pub enum CompressProgramError {
    Json(JsonError),
    Io(std::io::Error),
}
#[derive(Debug)]
pub struct JsonError {
    pub(crate) _message: String,
}
#[derive(Debug)]
pub struct BytecodeSegmentLengthMismatchError {
    pub segment_length: usize,
    pub bytecode_length: usize,
}
#[derive(Debug)]
pub struct InvalidBytecodeSegmentError {
    pub visited_pc: u64,
    pub segment_start: u64,
}
#[derive(Debug)]
pub struct PcOutOfRangeError {
    pub pc: u64,
}
#[derive(Error, Debug)]
pub enum CreationError {
    #[error("Class with hash {0:#x} is not declared, try using --class-hash with a hash of the declared class")]
    ClassHashNotFound(Felt),
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Provider error: {0:?}")]
    ProviderError(ProviderError),
    #[error("Invalid acc type {0}")]
    InvalidAccountType(String),
}

impl From<ProviderError> for CreationError {
    fn from(error: ProviderError) -> Self {
        CreationError::ProviderError(error)
    }
}

impl From<String> for CreationError {
    fn from(err: String) -> Self {
        CreationError::RpcError(err)
    }
}
#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Transaction has been rejected")]
    Rejected,
    #[error("Transaction has been reverted = {}", .0.data)]
    Reverted(ErrorData),
}
#[derive(Error, Debug)]
pub enum WaitForTransactionError {
    #[error(transparent)]
    TransactionError(TransactionError),
    #[error("sncast timed out while waiting for transaction to succeed")]
    TimedOut,
}

#[derive(Debug)]
pub struct ErrorData {
    pub data: String,
}
