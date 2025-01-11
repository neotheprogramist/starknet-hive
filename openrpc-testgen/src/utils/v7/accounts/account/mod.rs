use crate::utils::v7::providers::provider::{Provider, ProviderError};

use auto_impl::auto_impl;

use sha3::{Digest, Keccak256};

use starknet_types_core::felt::{Felt, NonZeroFelt};
use starknet_types_core::hash::{Poseidon, StarkHash};
use starknet_types_rpc::v0_7_1::{BlockId, BlockTag, ContractClass, SierraEntryPoint};
use std::{error::Error, sync::Arc};

use super::{
    call::Call,
    errors::{CompressProgramError, ComputeClassHashError},
};

mod declaration;
mod execution;

// 2 ** 251 - 256
const ADDR_BOUND: NonZeroFelt = NonZeroFelt::from_raw([
    576459263475590224,
    18446744073709255680,
    160989183,
    18446743986131443745,
]);

/// The standard Starknet account contract interface. It makes no assumption about the underlying
/// signer or provider. Account implementations that come with an active connection to the network
/// should also implement [ConnectedAccount] for useful functionalities like estimating fees and
/// sending transactions.

/// Converts Cairo short string to [Felt].
pub fn cairo_short_string_to_felt(str: &str) -> Result<Felt, CairoShortStringToFeltError> {
    if !str.is_ascii() {
        return Err(CairoShortStringToFeltError::NonAsciiCharacter);
    }
    if str.len() > 31 {
        return Err(CairoShortStringToFeltError::StringTooLong);
    }

    let ascii_bytes = str.as_bytes();

    let mut buffer = [0u8; 32];
    buffer[(32 - ascii_bytes.len())..].copy_from_slice(ascii_bytes);

    // The conversion will never fail
    Ok(Felt::from_bytes_be(&buffer))
}

#[derive(Debug)]
pub enum CairoShortStringToFeltError {
    NonAsciiCharacter,
    StringTooLong,
}
use std::fmt::Debug;
pub trait Account: ExecutionEncoder + Sized {
    type SignError: Error + Send + Sync;

    fn address(&self) -> Felt;

    fn chain_id(&self) -> Felt;

    fn sign_execution_v1(
        &self,
        execution: &RawExecutionV1,
        query_only: bool,
    ) -> impl std::future::Future<Output = Result<Vec<Felt>, Self::SignError>> + Send;

    fn sign_execution_v3(
        &self,
        execution: &RawExecutionV3,
        query_only: bool,
    ) -> impl std::future::Future<Output = Result<Vec<Felt>, Self::SignError>>;

    fn sign_declaration_v2(
        &self,
        declaration: &RawDeclarationV2,
        query_only: bool,
    ) -> impl std::future::Future<Output = Result<Vec<Felt>, Self::SignError>> + Send;

    fn sign_declaration_v3(
        &self,
        declaration: &RawDeclarationV3,
        query_only: bool,
    ) -> impl std::future::Future<Output = Result<Vec<Felt>, Self::SignError>>;

    fn is_signer_interactive(&self) -> bool;

    fn execute_v1(&self, calls: Vec<Call>) -> ExecutionV1<Self> {
        ExecutionV1::new(calls, self)
    }

    fn execute_v3(&self, calls: Vec<Call>) -> ExecutionV3<Self> {
        ExecutionV3::new(calls, self)
    }

    // #[deprecated = "use version specific variants (`execute_v1` & `execute_v3`) instead"]
    // fn execute(&self, calls: Vec<Call>) -> ExecutionV1<Self> {
    //     self.execute_v1(calls)
    // }

    fn declare_v2(
        &self,
        contract_class: Arc<ContractClass<Felt>>,
        compiled_class_hash: Felt,
    ) -> DeclarationV2<Self> {
        DeclarationV2::new(contract_class, compiled_class_hash, self)
    }

    fn declare_v3(
        &self,
        contract_class: ContractClass<Felt>,
        compiled_class_hash: Felt,
    ) -> DeclarationV3<Self>
    where
        Self: Debug,
    {
        DeclarationV3::new(contract_class, compiled_class_hash, self)
    }
}

#[auto_impl(&, Box, Arc)]
pub trait ExecutionEncoder {
    fn encode_calls(&self, calls: &[Call]) -> Vec<Felt>;
}

/// An [Account] implementation that also comes with a [Provider]. Functionalities that require a
/// connection to the sequencer or node are offloaded to this trait to keep the base [Account]
/// clean and flexible.
pub trait ConnectedAccount: Account {
    type Provider: Provider + Sync;

    fn provider(&self) -> &Self::Provider;

    /// Block ID to use when checking nonce and estimating fees.
    fn block_id(&self) -> BlockId<Felt> {
        BlockId::Tag(BlockTag::Pending)
    }

    fn get_nonce(&self) -> impl std::future::Future<Output = Result<Felt, ProviderError>> {
        async move {
            self.provider()
                .get_nonce(self.block_id(), self.address())
                .await
        }
    }
}

/// Abstraction over `INVOKE` transactions from accounts for invoking contracts. This struct uses
/// v1 `INVOKE` transactions under the hood, and hence pays transaction fees in ETH. To use v3
/// transactions for STRK fee payment, use [ExecutionV3] instead.
///
/// This is an intermediate type allowing users to optionally specify `nonce` and/or `max_fee`.
#[must_use]
#[derive(Debug)]
pub struct ExecutionV1<'a, A> {
    account: &'a A,
    calls: Vec<Call>,
    nonce: Option<Felt>,
    max_fee: Option<Felt>,
    fee_estimate_multiplier: f64,
}

/// Abstraction over `INVOKE` transactions from accounts for invoking contracts. This struct uses
/// v3 `INVOKE` transactions under the hood, and hence pays transaction fees in STRK. To use v1
/// transactions for ETH fee payment, use [ExecutionV1] instead.
///
/// This is an intermediate type allowing users to optionally specify `nonce`, `gas`, and/or
/// `gas_price`.
#[must_use]
#[derive(Debug)]
pub struct ExecutionV3<'a, A> {
    account: &'a A,
    calls: Vec<Call>,
    nonce: Option<Felt>,
    gas: Option<u64>,
    gas_price: Option<u128>,
    gas_estimate_multiplier: f64,
    gas_price_estimate_multiplier: f64,
}

/// Abstraction over `DECLARE` transactions from accounts for invoking contracts. This struct uses
/// v2 `DECLARE` transactions under the hood, and hence pays transaction fees in ETH. To use v3
/// transactions for STRK fee payment, use [DeclarationV3] instead.
///
/// An intermediate type allowing users to optionally specify `nonce` and/or `max_fee`.
#[must_use]
#[derive(Debug)]
pub struct DeclarationV2<'a, A> {
    account: &'a A,
    contract_class: Arc<ContractClass<Felt>>,
    compiled_class_hash: Felt,
    nonce: Option<Felt>,
    max_fee: Option<Felt>,
    fee_estimate_multiplier: f64,
}

/// Abstraction over `DECLARE` transactions from accounts for invoking contracts. This struct uses
/// v3 `DECLARE` transactions under the hood, and hence pays transaction fees in STRK. To use v2
/// transactions for ETH fee payment, use [DeclarationV2] instead.
///
/// This is an intermediate type allowing users to optionally specify `nonce`, `gas`, and/or
/// `gas_price`.
#[must_use]
#[derive(Debug)]
pub struct DeclarationV3<'a, A> {
    account: &'a A,
    contract_class: ContractClass<Felt>,
    compiled_class_hash: Felt,
    nonce: Option<Felt>,
    gas: Option<u64>,
    gas_price: Option<u128>,
    gas_estimate_multiplier: f64,
    gas_price_estimate_multiplier: f64,
}

/// [ExecutionV1] but with `nonce` and `max_fee` already determined.
#[derive(Debug)]
pub struct RawExecutionV1 {
    calls: Vec<Call>,
    nonce: Felt,
    max_fee: Felt,
}

/// [ExecutionV3] but with `nonce`, `gas` and `gas_price` already determined.
#[derive(Debug)]
pub struct RawExecutionV3 {
    calls: Vec<Call>,
    nonce: Felt,
    gas: u64,
    gas_price: u128,
}

/// [DeclarationV2] but with `nonce` and `max_fee` already determined.
#[derive(Debug)]
pub struct RawDeclarationV2 {
    contract_class: Arc<ContractClass<Felt>>,
    compiled_class_hash: Felt,
    nonce: Felt,
    max_fee: Felt,
}

const PREFIX_CONTRACT_CLASS_V0_1_0: Felt = Felt::from_raw([
    37302452645455172,
    18446734822722598327,
    15539482671244488427,
    5800711240972404213,
]);
pub trait ContractClassHasher {
    fn class_hash(&self) -> Felt;
}

impl ContractClassHasher for ContractClass<Felt> {
    fn class_hash(&self) -> Felt {
        let data = vec![
            PREFIX_CONTRACT_CLASS_V0_1_0,
            hash_entrypoints(&self.entry_points_by_type.external),
            hash_entrypoints(&self.entry_points_by_type.l1_handler),
            hash_entrypoints(&self.entry_points_by_type.constructor),
            starknet_keccak(self.abi.clone().expect("Abi expected").as_bytes()),
            Poseidon::hash_array(&self.sierra_program),
        ];

        normalize_address(Poseidon::hash_array(&data))
    }
}

pub fn normalize_address(address: Felt) -> Felt {
    address.mod_floor(&ADDR_BOUND)
}

pub fn hash_entrypoints(entrypoints: &[SierraEntryPoint<Felt>]) -> Felt {
    let mut data = Vec::new();

    for entry in entrypoints.iter() {
        data.push(entry.selector);
        data.push(entry.function_idx.into());
    }

    Poseidon::hash_array(&data)
}

// pub fn starknet_keccak(data: &[u8]) -> Felt {
//     let mut hasher = Keccak256::new();
//     hasher.update(data);
//     let mut hash = hasher.finalize();

//     // Remove the first 6 bits
//     hash[0] &= 0b00000011;

//     // Because we know hash is always 32 bytes
//     Felt::from_bytes_be(unsafe { &*(hash[..].as_ptr() as *const [u8; 32]) })
// }

pub fn starknet_keccak(data: &[u8]) -> Felt {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    // Convert hash to big-endian integer and mask to 250 bits
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash[..32]);
    hash_bytes[0] &= 0b00000011; // Ensure only the lowest 250 bits are kept

    Felt::from_bytes_be(&hash_bytes)
}

/// [DeclarationV3] but with `nonce`, `gas` and `gas_price` already determined.
#[derive(Debug)]
pub struct RawDeclarationV3 {
    contract_class: ContractClass<Felt>,
    compiled_class_hash: Felt,
    nonce: Felt,
    gas: u64,
    gas_price: u128,
}

/// [RawExecutionV1] but with an account associated.
#[derive(Debug)]
pub struct PreparedExecutionV1<'a, A> {
    account: &'a A,
    inner: RawExecutionV1,
}

/// [RawExecutionV3] but with an account associated.
#[derive(Debug)]
pub struct PreparedExecutionV3<'a, A> {
    account: &'a A,
    inner: RawExecutionV3,
}

/// [RawDeclarationV2] but with an account associated.
#[derive(Debug)]
pub struct PreparedDeclarationV2<'a, A> {
    account: &'a A,
    inner: RawDeclarationV2,
}

/// [RawDeclarationV3] but with an account associated.
#[derive(Debug)]
pub struct PreparedDeclarationV3<'a, A> {
    account: &'a A,
    inner: RawDeclarationV3,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError<S> {
    #[error(transparent)]
    Signing(S),
    #[error(transparent)]
    Provider(ProviderError),
    #[error("ComputeClassHashError ")]
    ClassHashCalculation(ComputeClassHashError),
    #[error("CompressProgramError")]
    ClassCompression(CompressProgramError),
    #[error("fee calculation overflow")]
    FeeOutOfRange,
    #[error("Other {0}")]
    Other(String),
}

impl<A> Account for &A
where
    A: Account + Sync,
{
    type SignError = A::SignError;

    fn address(&self) -> Felt {
        (*self).address()
    }

    fn chain_id(&self) -> Felt {
        (*self).chain_id()
    }

    async fn sign_execution_v1(
        &self,
        execution: &RawExecutionV1,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        (*self).sign_execution_v1(execution, query_only).await
    }

    async fn sign_execution_v3(
        &self,
        execution: &RawExecutionV3,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        (*self).sign_execution_v3(execution, query_only).await
    }

    async fn sign_declaration_v2(
        &self,
        declaration: &RawDeclarationV2,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        (*self).sign_declaration_v2(declaration, query_only).await
    }

    async fn sign_declaration_v3(
        &self,
        declaration: &RawDeclarationV3,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        (*self).sign_declaration_v3(declaration, query_only).await
    }

    fn is_signer_interactive(&self) -> bool {
        (*self).is_signer_interactive()
    }
}

impl<A> Account for Box<A>
where
    A: Account + Sync + Send,
{
    type SignError = A::SignError;

    fn address(&self) -> Felt {
        self.as_ref().address()
    }

    fn chain_id(&self) -> Felt {
        self.as_ref().chain_id()
    }

    async fn sign_execution_v1(
        &self,
        execution: &RawExecutionV1,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        self.as_ref().sign_execution_v1(execution, query_only).await
    }

    async fn sign_execution_v3(
        &self,
        execution: &RawExecutionV3,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        self.as_ref().sign_execution_v3(execution, query_only).await
    }

    async fn sign_declaration_v2(
        &self,
        declaration: &RawDeclarationV2,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        self.as_ref()
            .sign_declaration_v2(declaration, query_only)
            .await
    }

    async fn sign_declaration_v3(
        &self,
        declaration: &RawDeclarationV3,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        self.as_ref()
            .sign_declaration_v3(declaration, query_only)
            .await
    }
    fn is_signer_interactive(&self) -> bool {
        self.as_ref().is_signer_interactive()
    }
}

impl<A> Account for Arc<A>
where
    A: Account + Sync + Send,
{
    type SignError = A::SignError;

    fn address(&self) -> Felt {
        self.as_ref().address()
    }

    fn chain_id(&self) -> Felt {
        self.as_ref().chain_id()
    }

    async fn sign_execution_v1(
        &self,
        execution: &RawExecutionV1,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        self.as_ref().sign_execution_v1(execution, query_only).await
    }

    async fn sign_execution_v3(
        &self,
        execution: &RawExecutionV3,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        self.as_ref().sign_execution_v3(execution, query_only).await
    }

    async fn sign_declaration_v2(
        &self,
        declaration: &RawDeclarationV2,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        self.as_ref()
            .sign_declaration_v2(declaration, query_only)
            .await
    }

    async fn sign_declaration_v3(
        &self,
        declaration: &RawDeclarationV3,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        self.as_ref()
            .sign_declaration_v3(declaration, query_only)
            .await
    }

    fn is_signer_interactive(&self) -> bool {
        self.as_ref().is_signer_interactive()
    }

    fn execute_v1(&self, calls: Vec<Call>) -> ExecutionV1<Self> {
        ExecutionV1::new(calls, self)
    }

    fn execute_v3(&self, calls: Vec<Call>) -> ExecutionV3<Self> {
        ExecutionV3::new(calls, self)
    }

    // fn execute(&self, calls: Vec<Call>) -> ExecutionV1<Self> {
    //     self.execute_v1(calls)
    // }

    fn declare_v2(
        &self,
        contract_class: Arc<ContractClass<Felt>>,
        compiled_class_hash: Felt,
    ) -> DeclarationV2<Self> {
        DeclarationV2::new(contract_class, compiled_class_hash, self)
    }

    // fn declare(
    //     &self,
    //     contract_class: Arc<ContractClass<Felt>>,
    //     compiled_class_hash: Felt,
    // ) -> DeclarationV2<Self> {
    //     self.declare_v2(contract_class, compiled_class_hash)
    // }
}

impl<A> ConnectedAccount for &A
where
    A: ConnectedAccount + Sync,
{
    type Provider = A::Provider;

    fn provider(&self) -> &Self::Provider {
        (*self).provider()
    }

    fn block_id(&self) -> BlockId<Felt> {
        (*self).block_id()
    }

    async fn get_nonce(&self) -> Result<Felt, ProviderError> {
        (*self).get_nonce().await
    }
}

impl<A> ConnectedAccount for Box<A>
where
    A: ConnectedAccount + Sync + Send,
{
    type Provider = A::Provider;

    fn provider(&self) -> &Self::Provider {
        self.as_ref().provider()
    }

    fn block_id(&self) -> BlockId<Felt> {
        self.as_ref().block_id()
    }

    async fn get_nonce(&self) -> Result<Felt, ProviderError> {
        self.as_ref().get_nonce().await
    }
}

impl<A> ConnectedAccount for Arc<A>
where
    A: ConnectedAccount + Sync + Send,
{
    type Provider = A::Provider;

    fn provider(&self) -> &Self::Provider {
        self.as_ref().provider()
    }

    fn block_id(&self) -> BlockId<Felt> {
        self.as_ref().block_id()
    }

    async fn get_nonce(&self) -> Result<Felt, ProviderError> {
        self.as_ref().get_nonce().await
    }
}
