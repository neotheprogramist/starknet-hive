use super::errors::NotPreparedError;

use serde::{Deserialize, Serialize};

use crypto_utils::curve::signer::compute_hash_on_elements;
use starknet_types_core::felt::Felt;
use starknet_types_core::felt::NonZeroFelt;
use starknet_types_core::hash::{Poseidon, StarkHash};
use starknet_types_rpc::v0_7_1::{
    BlockId, BlockTag, BroadcastedDeployAccountTxn, BroadcastedTxn, ContractAndTxnHash,
    DeployAccountTxnV1, FeeEstimate, SimulateTransactionsResult, SimulationFlag,
};
use starknet_types_rpc::{
    DaMode, DeployAccountTxnV3, MaybePendingBlockWithTxHashes, ResourceBounds,
    ResourceBoundsMapping,
};

use crate::utils::v7::providers::{
    jsonrpc::StarknetError,
    provider::{Provider, ProviderError},
};
use std::error::Error;

pub mod open_zeppelin;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataAvailabilityMode {
    #[serde(rename = "L1")]
    L1,
    #[serde(rename = "L2")]
    L2,
}

/// Cairo string for "deploy_account"
const PREFIX_DEPLOY_ACCOUNT: Felt = Felt::from_raw([
    461298303000467581,
    18446744073709551615,
    18443211694809419988,
    3350261884043292318,
]);

/// Cairo string for "STARKNET_CONTRACT_ADDRESS"
const PREFIX_CONTRACT_ADDRESS: Felt = Felt::from_raw([
    533439743893157637,
    8635008616843941496,
    17289941567720117366,
    3829237882463328880,
]);

// 2 ** 251 - 256
const ADDR_BOUND: NonZeroFelt = NonZeroFelt::from_raw([
    576459263475590224,
    18446744073709255680,
    160989183,
    18446743986131443745,
]);

/// This trait enables deploying account contracts using the `DeployAccount` transaction type.
pub trait AccountFactory: Sized {
    type Provider: Provider + Sync;
    type SignError: Error + Send + Sync;

    fn class_hash(&self) -> Felt;

    fn calldata(&self) -> Vec<Felt>;

    fn chain_id(&self) -> Felt;

    fn provider(&self) -> &Self::Provider;

    /// Whether the underlying signer implementation is interactive, such as a hardware wallet.
    /// Implementations should return `true` if the signing operation is very expensive, even if not
    /// strictly "interactive" as in requiring human input.
    ///
    /// This affects how an account factory makes decision on whether to request a real signature
    /// for estimation/simulation purposes.
    fn is_signer_interactive(&self) -> bool;

    /// Block ID to use when estimating fees.
    fn block_id(&self) -> BlockId<Felt> {
        BlockId::Tag(BlockTag::Latest)
    }

    fn sign_deployment_v1(
        &self,
        deployment: &RawAccountDeploymentV1,
        query_only: bool,
    ) -> impl std::future::Future<Output = Result<Vec<Felt>, Self::SignError>> + Send;

    fn sign_deployment_v3(
        &self,
        deployment: &RawAccountDeploymentV3,
        query_only: bool,
    ) -> impl std::future::Future<Output = Result<Vec<Felt>, Self::SignError>>;

    fn deploy_v1(&self, salt: Felt) -> AccountDeploymentV1<Self> {
        AccountDeploymentV1::new(salt, self)
    }

    fn deploy_v3(&self, salt: Felt) -> AccountDeploymentV3<Self> {
        AccountDeploymentV3::new(salt, self)
    }

    #[deprecated = "use version specific variants (`deploy_v1` & `deploy_v3`) instead"]
    fn deploy(&self, salt: Felt) -> AccountDeploymentV3<Self> {
        self.deploy_v3(salt)
    }
}

/// Abstraction over `DEPLOY_ACCOUNT` transactions for account contract deployment. This struct uses
/// v1 `DEPLOY_ACCOUNT` transactions under the hood, and hence pays transaction fees in ETH. To use
/// v3 transactions for STRK fee payment, use [AccountDeploymentV3] instead.
///
/// An intermediate type allowing users to optionally specify `nonce` and/or `max_fee`.
#[must_use]
#[derive(Debug)]
pub struct AccountDeploymentV1<'f, F> {
    factory: &'f F,
    salt: Felt,
    // We need to allow setting nonce here as `DeployAccount` transactions may have non-zero nonces
    /// after failed transactions can be included in blocks.
    nonce: Option<Felt>,
    max_fee: Option<Felt>,
    fee_estimate_multiplier: f64,
}

/// Abstraction over `DEPLOY_ACCOUNT` transactions for account contract deployment. This struct uses
/// v3 `DEPLOY_ACCOUNT` transactions under the hood, and hence pays transaction fees in STRK. To use
/// v1 transactions for ETH fee payment, use [AccountDeploymentV1] instead.
///
/// This is an intermediate type allowing users to optionally specify `nonce`, `gas`, and/or
/// `gas_price`.
#[must_use]
#[derive(Debug)]
pub struct AccountDeploymentV3<'f, F> {
    factory: &'f F,
    salt: Felt,
    // We need to allow setting nonce here as `DeployAccount` transactions may have non-zero nonces
    /// after failed transactions can be included in blocks.
    nonce: Option<Felt>,
    gas: Option<u64>,
    gas_price: Option<u128>,
    gas_estimate_multiplier: f64,
    gas_price_estimate_multiplier: f64,
}

/// [AccountDeploymentV1] but with `nonce` and `max_fee` already determined.
#[derive(Debug, Clone)]
pub struct RawAccountDeploymentV1 {
    salt: Felt,
    nonce: Felt,
    max_fee: Felt,
}

/// [AccountDeploymentV3] but with `nonce`, `gas` and `gas_price` already determined.
#[derive(Debug, Clone)]
pub struct RawAccountDeploymentV3 {
    salt: Felt,
    nonce: Felt,
    gas: u64,
    gas_price: u128,
}

/// [RawAccountDeploymentV1] but with a factory associated.
#[derive(Debug)]
pub struct PreparedAccountDeploymentV1<'f, F> {
    factory: &'f F,
    inner: RawAccountDeploymentV1,
}

/// [RawAccountDeploymentV3] but with a factory associated.
#[derive(Debug)]
pub struct PreparedAccountDeploymentV3<'f, F> {
    factory: &'f F,
    inner: RawAccountDeploymentV3,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountFactoryError<S> {
    #[error(transparent)]
    Signing(S),
    #[error(transparent)]
    Provider(ProviderError),
    #[error("fee calculation overflow")]
    FeeOutOfRange,
}
impl<'f, F> AccountDeploymentV1<'f, F> {
    pub fn new(salt: Felt, factory: &'f F) -> Self {
        Self {
            factory,
            salt,
            nonce: None,
            max_fee: None,
            fee_estimate_multiplier: 1.1,
        }
    }

    pub fn nonce(self, nonce: Felt) -> Self {
        Self {
            nonce: Some(nonce),
            ..self
        }
    }

    pub fn max_fee(self, max_fee: Felt) -> Self {
        Self {
            max_fee: Some(max_fee),
            ..self
        }
    }

    pub fn fee_estimate_multiplier(self, fee_estimate_multiplier: f64) -> Self {
        Self {
            fee_estimate_multiplier,
            ..self
        }
    }

    /// Calling this function after manually specifying `nonce` and `max_fee` turns
    /// [AccountDeploymentV1] into [PreparedAccountDeploymentV1]. Returns `Err` if either field is
    /// `None`.
    pub fn prepared(self) -> Result<PreparedAccountDeploymentV1<'f, F>, NotPreparedError> {
        let nonce = self.nonce.ok_or(NotPreparedError)?;
        let max_fee = self.max_fee.ok_or(NotPreparedError)?;

        Ok(PreparedAccountDeploymentV1 {
            factory: self.factory,
            inner: RawAccountDeploymentV1 {
                salt: self.salt,
                nonce,
                max_fee,
            },
        })
    }
}
impl<'f, F> AccountDeploymentV3<'f, F> {
    pub fn new(salt: Felt, factory: &'f F) -> Self {
        Self {
            factory,
            salt,
            nonce: None,
            gas: None,
            gas_price: None,
            gas_estimate_multiplier: 1.5,
            gas_price_estimate_multiplier: 1.5,
        }
    }

    pub fn nonce(self, nonce: Felt) -> Self {
        Self {
            nonce: Some(nonce),
            ..self
        }
    }

    pub fn gas(self, gas: u64) -> Self {
        Self {
            gas: Some(gas),
            ..self
        }
    }

    pub fn gas_price(self, gas_price: u128) -> Self {
        Self {
            gas_price: Some(gas_price),
            ..self
        }
    }

    pub fn gas_estimate_multiplier(self, gas_estimate_multiplier: f64) -> Self {
        Self {
            gas_estimate_multiplier,
            ..self
        }
    }

    pub fn gas_price_estimate_multiplier(self, gas_price_estimate_multiplier: f64) -> Self {
        Self {
            gas_price_estimate_multiplier,
            ..self
        }
    }

    /// Calling this function after manually specifying `nonce` and `max_fee` turns
    /// [AccountDeploymentV3] into [PreparedAccountDeploymentV3]. Returns `Err` if either field is
    /// `None`.
    pub fn prepared(self) -> Result<PreparedAccountDeploymentV3<'f, F>, NotPreparedError> {
        let nonce = self.nonce.ok_or(NotPreparedError)?;
        let gas = self.gas.ok_or(NotPreparedError)?;
        let gas_price = self.gas_price.ok_or(NotPreparedError)?;

        Ok(PreparedAccountDeploymentV3 {
            factory: self.factory,
            inner: RawAccountDeploymentV3 {
                salt: self.salt,
                nonce,
                gas,
                gas_price,
            },
        })
    }
}

impl<'f, F> AccountDeploymentV1<'f, F>
where
    F: AccountFactory + Sync,
{
    /// Locally calculates the target deployment address.
    pub fn address(&self) -> Felt {
        calculate_contract_address(
            self.salt,
            self.factory.class_hash(),
            &self.factory.calldata(),
        )
    }

    pub async fn fetch_nonce(&self) -> Result<Felt, ProviderError> {
        match self
            .factory
            .provider()
            .get_nonce(self.factory.block_id(), self.address())
            .await
        {
            Ok(nonce) => Ok(nonce),
            Err(ProviderError::StarknetError(StarknetError::ContractNotFound)) => Ok(Felt::ZERO),
            Err(err) => Err(err),
        }
    }

    pub async fn estimate_fee(
        &self,
    ) -> Result<FeeEstimate<Felt>, AccountFactoryError<F::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .fetch_nonce()
                .await
                .map_err(AccountFactoryError::Provider)?,
        };

        self.estimate_fee_with_nonce(nonce).await
    }

    pub async fn simulate(
        &self,
        skip_validate: bool,
        skip_fee_charge: bool,
    ) -> Result<SimulateTransactionsResult<Felt>, AccountFactoryError<F::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .fetch_nonce()
                .await
                .map_err(AccountFactoryError::Provider)?,
        };

        self.simulate_with_nonce(nonce, skip_validate, skip_fee_charge)
            .await
    }

    pub async fn send(
        &self,
    ) -> Result<ContractAndTxnHash<Felt>, AccountFactoryError<F::SignError>> {
        self.prepare().await?.send().await
    }

    pub async fn prepare(
        &self,
    ) -> Result<PreparedAccountDeploymentV1<'f, F>, AccountFactoryError<F::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .fetch_nonce()
                .await
                .map_err(AccountFactoryError::Provider)?,
        };

        // Resolves max_fee
        let max_fee = match self.max_fee {
            Some(value) => value,
            None => {
                // TODO: remove this when a proper u64 conversion is implemented for `Felt`
                // Obtain the fee estimate
                let fee_estimate = self.estimate_fee_with_nonce(nonce).await?;
                // Convert the overall fee to little-endian bytes
                let overall_fee_bytes = fee_estimate.overall_fee.to_bytes_le();

                // Check if the remaining bytes after the first 8 are all zeros
                if overall_fee_bytes.iter().skip(8).any(|&x| x != 0) {
                    return Err(AccountFactoryError::FeeOutOfRange);
                }

                // Convert the first 8 bytes to u64
                let overall_fee_u64 =
                    u64::from_le_bytes(overall_fee_bytes[..8].try_into().unwrap());

                // Perform necessary operations on overall_fee_u64 and convert to f64 then to u64
                (((overall_fee_u64 as f64) * self.fee_estimate_multiplier) as u64).into()
            }
        };
        let res: PreparedAccountDeploymentV1<F> = PreparedAccountDeploymentV1 {
            factory: self.factory,
            inner: RawAccountDeploymentV1 {
                salt: self.salt,
                nonce,
                max_fee,
            },
        };

        Ok(res)
    }

    async fn estimate_fee_with_nonce(
        &self,
        nonce: Felt,
    ) -> Result<FeeEstimate<Felt>, AccountFactoryError<F::SignError>> {
        let skip_signature = self.factory.is_signer_interactive();

        let prepared = PreparedAccountDeploymentV1 {
            factory: self.factory,
            inner: RawAccountDeploymentV1 {
                salt: self.salt,
                nonce,
                max_fee: Felt::ZERO,
            },
        };

        let deploy = prepared
            .get_deploy_request(false, skip_signature)
            .await
            .map_err(AccountFactoryError::Signing)?;

        self.factory
            .provider()
            .estimate_fee_single(
                BroadcastedTxn::DeployAccount(BroadcastedDeployAccountTxn::V1(deploy)),
                vec![],
                self.factory.block_id(),
            )
            .await
            .map_err(AccountFactoryError::Provider)
    }

    async fn simulate_with_nonce(
        &self,
        nonce: Felt,
        skip_validate: bool,
        skip_fee_charge: bool,
    ) -> Result<SimulateTransactionsResult<Felt>, AccountFactoryError<F::SignError>> {
        let skip_signature = if self.factory.is_signer_interactive() {
            // If signer is interactive, we would try to minimize signing requests. However, if the
            // caller has decided to not skip validation, it's best we still request a real
            // signature, as otherwise the simulation would most likely fail.
            skip_validate
        } else {
            // Signing with non-interactive signers is cheap so always request signatures.
            false
        };

        let prepared = PreparedAccountDeploymentV1 {
            factory: self.factory,
            inner: RawAccountDeploymentV1 {
                salt: self.salt,
                nonce,
                max_fee: self.max_fee.unwrap_or_default(),
            },
        };
        let deploy = prepared
            .get_deploy_request(true, skip_signature)
            .await
            .map_err(AccountFactoryError::Signing)?;

        let mut flags = vec![];

        if !skip_validate {
            flags.push(SimulationFlag::Validate);
        }
        if !skip_fee_charge {
            flags.push(SimulationFlag::FeeCharge);
        }

        self.factory
            .provider()
            .simulate_transaction(
                self.factory.block_id(),
                BroadcastedTxn::DeployAccount(BroadcastedDeployAccountTxn::V1(deploy)),
                flags,
            )
            .await
            .map_err(AccountFactoryError::Provider)
    }
}

impl<'f, F> AccountDeploymentV3<'f, F>
where
    F: AccountFactory + Sync,
{
    /// Locally calculates the target deployment address.
    pub fn address(&self) -> Felt {
        calculate_contract_address(
            self.salt,
            self.factory.class_hash(),
            &self.factory.calldata(),
        )
    }

    pub async fn fetch_nonce(&self) -> Result<Felt, ProviderError> {
        match self
            .factory
            .provider()
            .get_nonce(self.factory.block_id(), self.address())
            .await
        {
            Ok(nonce) => Ok(nonce),
            Err(ProviderError::StarknetError(StarknetError::ContractNotFound)) => Ok(Felt::ZERO),
            Err(err) => Err(err),
        }
    }

    pub async fn estimate_fee(
        &self,
    ) -> Result<FeeEstimate<Felt>, AccountFactoryError<F::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .fetch_nonce()
                .await
                .map_err(AccountFactoryError::Provider)?,
        };

        self.estimate_fee_with_nonce(nonce).await
    }

    pub async fn estimate_fee_skip_signature(
        &self,
    ) -> Result<FeeEstimate<Felt>, AccountFactoryError<F::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .fetch_nonce()
                .await
                .map_err(AccountFactoryError::Provider)?,
        };

        self.estimate_fee_with_nonce_skip_signature(nonce).await
    }

    pub async fn simulate(
        &self,
        skip_validate: bool,
        skip_fee_charge: bool,
    ) -> Result<SimulateTransactionsResult<Felt>, AccountFactoryError<F::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .fetch_nonce()
                .await
                .map_err(AccountFactoryError::Provider)?,
        };

        self.simulate_with_nonce(nonce, skip_validate, skip_fee_charge)
            .await
    }

    pub async fn send(
        &self,
    ) -> Result<ContractAndTxnHash<Felt>, AccountFactoryError<F::SignError>> {
        self.prepare().await?.send().await
    }

    pub async fn prepare(
        &self,
    ) -> Result<PreparedAccountDeploymentV3<'f, F>, AccountFactoryError<F::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .fetch_nonce()
                .await
                .map_err(AccountFactoryError::Provider)?,
        };

        // Resolves fee settings
        let (gas, gas_price) = match (self.gas, self.gas_price) {
            (Some(gas), Some(gas_price)) => (gas, gas_price),
            (Some(gas), _) => {
                // When `gas` is specified, we only need the L1 gas price in FRI. By specifying a
                // a `gas` value, the user might be trying to avoid a full fee estimation (e.g.
                // flaky dependencies), so it's in appropriate to call `estimate_fee` here.

                // This is the lightest-weight block we can get
                let block_result = self
                    .factory
                    .provider()
                    .get_block_with_tx_hashes(self.factory.block_id())
                    .await
                    .map_err(AccountFactoryError::Provider)?;

                let block_l1_gas_price = match block_result {
                    MaybePendingBlockWithTxHashes::Block(block) => {
                        // Extract the L1 gas price from the Block
                        block.block_header.l1_gas_price.price_in_fri
                    }
                    MaybePendingBlockWithTxHashes::Pending(pending_block) => {
                        // Extract the L1 gas price from the PendingBlock
                        pending_block.pending_block_header.l1_gas_price.price_in_fri
                    }
                };

                let block_l1_gas_price_bytes = block_l1_gas_price.to_bytes_le();
                if block_l1_gas_price_bytes.iter().skip(8).any(|&x| x != 0) {
                    return Err(AccountFactoryError::FeeOutOfRange);
                }
                let block_l1_gas_price =
                    u64::from_le_bytes(block_l1_gas_price_bytes[..8].try_into().unwrap());

                let gas_price =
                    ((block_l1_gas_price as f64) * self.gas_price_estimate_multiplier) as u128;

                (gas, gas_price)
            }
            // We have to perform fee estimation as long as gas is not specified
            _ => {
                let fee_estimate = self.estimate_fee_with_nonce(nonce).await?;

                let gas = match self.gas {
                    Some(gas) => gas,
                    None => {
                        let overall_fee_bytes = fee_estimate.overall_fee.to_bytes_le();
                        if overall_fee_bytes.iter().skip(8).any(|&x| x != 0) {
                            return Err(AccountFactoryError::FeeOutOfRange);
                        }
                        let overall_fee =
                            u64::from_le_bytes(overall_fee_bytes[..8].try_into().unwrap());

                        let gas_price_bytes = fee_estimate.gas_price.to_bytes_le();
                        if gas_price_bytes.iter().skip(8).any(|&x| x != 0) {
                            return Err(AccountFactoryError::FeeOutOfRange);
                        }
                        let gas_price =
                            u64::from_le_bytes(gas_price_bytes[..8].try_into().unwrap());

                        ((((overall_fee + gas_price - 1) / gas_price) as f64)
                            * self.gas_estimate_multiplier) as u64
                    }
                };

                let gas_price = match self.gas_price {
                    Some(gas_price) => gas_price,
                    None => {
                        let gas_price_bytes = fee_estimate.gas_price.to_bytes_le();
                        if gas_price_bytes.iter().skip(8).any(|&x| x != 0) {
                            return Err(AccountFactoryError::FeeOutOfRange);
                        }
                        let gas_price =
                            u64::from_le_bytes(gas_price_bytes[..8].try_into().unwrap());

                        ((gas_price as f64) * self.gas_price_estimate_multiplier) as u128
                    }
                };

                (gas, gas_price)
            }
        };

        Ok(PreparedAccountDeploymentV3 {
            factory: self.factory,
            inner: RawAccountDeploymentV3 {
                salt: self.salt,
                nonce,
                gas,
                gas_price,
            },
        })
    }

    async fn estimate_fee_with_nonce(
        &self,
        nonce: Felt,
    ) -> Result<FeeEstimate<Felt>, AccountFactoryError<F::SignError>> {
        let skip_signature = self.factory.is_signer_interactive();

        let prepared = PreparedAccountDeploymentV3 {
            factory: self.factory,
            inner: RawAccountDeploymentV3 {
                salt: self.salt,
                nonce,
                gas: 0,
                gas_price: 0,
            },
        };
        let deploy = prepared
            .get_deploy_request(false, skip_signature)
            .await
            .map_err(AccountFactoryError::Signing)?;

        self.factory
            .provider()
            .estimate_fee_single(
                BroadcastedTxn::DeployAccount(BroadcastedDeployAccountTxn::V3(deploy)),
                if skip_signature {
                    // Validation would fail since real signature was not requested
                    vec!["SKIP_VALIDATE".to_string()]
                } else {
                    // With the correct signature in place, run validation for accurate results
                    vec![]
                },
                self.factory.block_id(),
            )
            .await
            .map_err(AccountFactoryError::Provider)
    }

    async fn estimate_fee_with_nonce_skip_signature(
        &self,
        nonce: Felt,
    ) -> Result<FeeEstimate<Felt>, AccountFactoryError<F::SignError>> {
        let skip_signature = true;

        let prepared = PreparedAccountDeploymentV3 {
            factory: self.factory,
            inner: RawAccountDeploymentV3 {
                salt: self.salt,
                nonce,
                gas: 0,
                gas_price: 0,
            },
        };
        let deploy = prepared
            .get_deploy_request(false, skip_signature)
            .await
            .map_err(AccountFactoryError::Signing)?;

        self.factory
            .provider()
            .estimate_fee_single(
                BroadcastedTxn::DeployAccount(BroadcastedDeployAccountTxn::V3(deploy)),
                if skip_signature {
                    // Validation would fail since real signature was not requested
                    vec!["SKIP_VALIDATE".to_string()]
                } else {
                    // With the correct signature in place, run validation for accurate results
                    vec![]
                },
                self.factory.block_id(),
            )
            .await
            .map_err(AccountFactoryError::Provider)
    }
    async fn simulate_with_nonce(
        &self,
        nonce: Felt,
        skip_validate: bool,
        skip_fee_charge: bool,
    ) -> Result<SimulateTransactionsResult<Felt>, AccountFactoryError<F::SignError>> {
        let skip_signature = if self.factory.is_signer_interactive() {
            // If signer is interactive, we would try to minimize signing requests. However, if the
            // caller has decided to not skip validation, it's best we still request a real
            // signature, as otherwise the simulation would most likely fail.
            skip_validate
        } else {
            // Signing with non-interactive signers is cheap so always request signatures.
            false
        };

        let prepared = PreparedAccountDeploymentV3 {
            factory: self.factory,
            inner: RawAccountDeploymentV3 {
                salt: self.salt,
                nonce,
                gas: self.gas.unwrap_or_default(),
                gas_price: self.gas_price.unwrap_or_default(),
            },
        };
        let deploy = prepared
            .get_deploy_request(false, skip_signature)
            .await
            .map_err(AccountFactoryError::Signing)?;

        let mut flags = vec![];

        if skip_validate {
            flags.push(SimulationFlag::Validate);
        }
        if skip_fee_charge {
            flags.push(SimulationFlag::FeeCharge);
        }

        self.factory
            .provider()
            .simulate_transaction(
                self.factory.block_id(),
                BroadcastedTxn::DeployAccount(BroadcastedDeployAccountTxn::V3(deploy)),
                flags,
            )
            .await
            .map_err(AccountFactoryError::Provider)
    }
}

impl RawAccountDeploymentV1 {
    pub fn salt(&self) -> Felt {
        self.salt
    }

    pub fn nonce(&self) -> Felt {
        self.nonce
    }

    pub fn max_fee(&self) -> Felt {
        self.max_fee
    }
}

impl RawAccountDeploymentV3 {
    pub fn salt(&self) -> Felt {
        self.salt
    }

    pub fn nonce(&self) -> Felt {
        self.nonce
    }

    pub fn gas(&self) -> u64 {
        self.gas
    }

    pub fn gas_price(&self) -> u128 {
        self.gas_price
    }
}

impl<'f, F> PreparedAccountDeploymentV1<'f, F> {
    pub fn from_raw(raw_deployment: RawAccountDeploymentV1, factory: &'f F) -> Self {
        Self {
            factory,
            inner: raw_deployment,
        }
    }
}

impl<'f, F> PreparedAccountDeploymentV3<'f, F> {
    pub fn from_raw(raw_deployment: RawAccountDeploymentV3, factory: &'f F) -> Self {
        Self {
            factory,
            inner: raw_deployment,
        }
    }
}

impl<'f, F> PreparedAccountDeploymentV1<'f, F>
where
    F: AccountFactory,
{
    /// Locally calculates the target deployment address.
    pub fn address(&self) -> Felt {
        calculate_contract_address(
            self.inner.salt,
            self.factory.class_hash(),
            &self.factory.calldata(),
        )
    }

    pub fn transaction_hash(&self, _query_only: bool) -> Felt {
        let mut calldata_to_hash = vec![self.factory.class_hash(), self.inner.salt];
        calldata_to_hash.append(&mut self.factory.calldata());

        compute_hash_on_elements(&[
            PREFIX_DEPLOY_ACCOUNT,
            Felt::ONE,
            self.address(),
            Felt::ZERO, // entry_point_selector
            compute_hash_on_elements(&calldata_to_hash),
            self.inner.max_fee,
            self.factory.chain_id(),
            self.inner.nonce,
        ])
    }

    pub async fn send(
        &self,
    ) -> Result<ContractAndTxnHash<Felt>, AccountFactoryError<F::SignError>> {
        let tx_request = self
            .get_deploy_request(false, false)
            .await
            .map_err(AccountFactoryError::Signing)?;

        self.factory
            .provider()
            .add_deploy_account_transaction(BroadcastedTxn::DeployAccount(
                BroadcastedDeployAccountTxn::V1(tx_request),
            ))
            .await
            .map_err(AccountFactoryError::Provider)
    }

    pub async fn get_deploy_request(
        &self,
        query_only: bool,
        skip_signature: bool,
    ) -> Result<DeployAccountTxnV1<Felt>, F::SignError> {
        let signature = if skip_signature {
            vec![]
        } else {
            self.factory
                .sign_deployment_v1(&self.inner, query_only)
                .await?
        };

        let txn = DeployAccountTxnV1 {
            max_fee: self.inner.max_fee,
            signature,
            nonce: self.inner.nonce,
            contract_address_salt: self.inner.salt,
            constructor_calldata: self.factory.calldata(),
            class_hash: self.factory.class_hash(),
        };

        Ok(txn)
    }
}

impl<'f, F> PreparedAccountDeploymentV3<'f, F>
where
    F: AccountFactory,
{
    /// Locally calculates the target deployment address.
    pub fn address(&self) -> Felt {
        calculate_contract_address(
            self.inner.salt,
            self.factory.class_hash(),
            &self.factory.calldata(),
        )
    }

    pub fn transaction_hash(&self, _query_only: bool) -> Felt {
        // Main data vector to collect all elements for hashing
        let mut data = vec![PREFIX_DEPLOY_ACCOUNT, Felt::THREE, self.address()];

        // Fee data collection
        let mut fee_data = vec![Felt::ZERO]; // Hard-coded fee market

        // First L1 gas resource buffer
        let mut resource_buffer = [
            0, 0, b'L', b'1', b'_', b'G', b'A', b'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        resource_buffer[8..(8 + 8)].copy_from_slice(&self.inner.gas.to_be_bytes());
        resource_buffer[(8 + 8)..].copy_from_slice(&self.inner.gas_price.to_be_bytes());
        fee_data.push(Felt::from_bytes_be(&resource_buffer));

        // Second L2 gas resource buffer
        let resource_buffer = [
            0, 0, b'L', b'2', b'_', b'G', b'A', b'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        fee_data.push(Felt::from_bytes_be(&resource_buffer));

        // Hash the fee data and add it to main data
        data.push(Poseidon::hash_array(&fee_data));

        // Hard-coded empty `paymaster_data`
        data.push(Poseidon::hash_array(&[]));

        // Remaining transaction fields
        data.push(self.factory.chain_id());
        data.push(self.inner.nonce);
        data.push(Felt::ZERO); // Hard-coded L1 DA mode for nonce and fee

        // Calldata hashing
        let calldata_elements: Vec<Felt> = self.factory.calldata();
        data.push(Poseidon::hash_array(&calldata_elements));

        // Final elements
        data.push(self.factory.class_hash());
        data.push(self.inner.salt);

        // Final hash computation
        Poseidon::hash_array(&data)
    }

    pub async fn send(
        &self,
    ) -> Result<ContractAndTxnHash<Felt>, AccountFactoryError<F::SignError>> {
        let tx_request = self
            .get_deploy_request(false, false)
            .await
            .map_err(AccountFactoryError::Signing)?;
        self.factory
            .provider()
            .add_deploy_account_transaction(BroadcastedTxn::DeployAccount(
                BroadcastedDeployAccountTxn::V3(tx_request),
            ))
            .await
            .map_err(AccountFactoryError::Provider)
    }

    pub async fn get_deploy_request(
        &self,
        _query_only: bool,
        skip_signature: bool,
    ) -> Result<DeployAccountTxnV3<Felt>, F::SignError> {
        Ok(DeployAccountTxnV3 {
            signature: if skip_signature {
                vec![]
            } else {
                self.factory.sign_deployment_v3(&self.inner, false).await?
            },
            nonce: self.inner.nonce,
            contract_address_salt: self.inner.salt,
            constructor_calldata: self.factory.calldata(),
            class_hash: self.factory.class_hash(),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds {
                    max_amount: Felt::from_dec_str(&self.inner.gas.to_string())
                        .unwrap()
                        .to_hex_string(),
                    max_price_per_unit: Felt::from_dec_str(&self.inner.gas_price.to_string())
                        .unwrap()
                        .to_hex_string(),
                },
                // L2 resources are hard-coded to 0
                l2_gas: ResourceBounds {
                    max_amount: "0x0".to_string(),
                    max_price_per_unit: "0x0".to_string(),
                },
            },
            // Fee market has not been been activated yet so it's hard-coded to be 0
            tip: Felt::ZERO,
            // Hard-coded empty `paymaster_data`
            paymaster_data: vec![],
            // Hard-coded L1 DA mode for nonce and fee
            nonce_data_availability_mode: DaMode::L1,
            fee_data_availability_mode: DaMode::L1,
            // is_query: query_only,
        })
    }
}

fn calculate_contract_address(salt: Felt, class_hash: Felt, constructor_calldata: &[Felt]) -> Felt {
    compute_hash_on_elements(&[
        PREFIX_CONTRACT_ADDRESS,
        Felt::ZERO,
        salt,
        class_hash,
        compute_hash_on_elements(constructor_calldata),
    ])
    .mod_floor(&ADDR_BOUND)
}
