use crate::utils::v7::accounts::account::ContractClassHasher;

use crate::utils::v7::{accounts::errors::NotPreparedError, providers::provider::Provider};

use crypto_utils::curve::signer::compute_hash_on_elements;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};
use starknet_types_rpc::v0_7_1::{
    BroadcastedDeclareTxn, BroadcastedDeclareTxnV2, BroadcastedDeclareTxnV3, BroadcastedTxn,
    ClassAndTxnHash, ContractClass, FeeEstimate, SimulateTransactionsResult, SimulationFlag,
};
use starknet_types_rpc::{
    DaMode, MaybePendingBlockWithTxHashes, ResourceBounds, ResourceBoundsMapping,
};
use std::sync::Arc;

use super::{
    Account, AccountError, ConnectedAccount, DeclarationV2, DeclarationV3, PreparedDeclarationV2,
    PreparedDeclarationV3, RawDeclarationV2, RawDeclarationV3,
};

/// Cairo string for "declare"
const PREFIX_DECLARE: Felt = Felt::from_raw([
    191557713328401194,
    18446744073709551615,
    18446744073709551615,
    17542456862011667323,
]);

/// 2 ^ 128 + 2
const QUERY_VERSION_TWO: Felt = Felt::from_raw([
    576460752142433232,
    18446744073709551584,
    17407,
    18446744073700081601,
]);
impl<'a, A> DeclarationV2<'a, A> {
    pub fn new(
        contract_class: Arc<ContractClass<Felt>>,
        compiled_class_hash: Felt,
        account: &'a A,
    ) -> Self {
        Self {
            account,
            contract_class,
            compiled_class_hash,
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

    /// Calling this function after manually specifying `nonce` and `max_fee` turns [DeclarationV2]
    /// into [PreparedDeclarationV2]. Returns `Err` if either field is `None`.
    pub fn prepared(self) -> Result<PreparedDeclarationV2<'a, A>, NotPreparedError> {
        let nonce = self.nonce.ok_or(NotPreparedError)?;
        let max_fee = self.max_fee.ok_or(NotPreparedError)?;

        Ok(PreparedDeclarationV2 {
            account: self.account,
            inner: RawDeclarationV2 {
                contract_class: self.contract_class,
                compiled_class_hash: self.compiled_class_hash,
                nonce,
                max_fee,
            },
        })
    }
}
impl<'a, A> DeclarationV2<'a, A>
where
    A: ConnectedAccount + Sync,
{
    pub async fn estimate_fee(&self) -> Result<FeeEstimate<Felt>, AccountError<A::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .account
                .get_nonce()
                .await
                .map_err(AccountError::Provider)?,
        };

        self.estimate_fee_with_nonce(nonce).await
    }

    pub async fn simulate(
        &self,
        skip_validate: bool,
        skip_fee_charge: bool,
    ) -> Result<SimulateTransactionsResult<Felt>, AccountError<A::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .account
                .get_nonce()
                .await
                .map_err(AccountError::Provider)?,
        };

        self.simulate_with_nonce(nonce, skip_validate, skip_fee_charge)
            .await
    }

    pub async fn send(&self) -> Result<ClassAndTxnHash<Felt>, AccountError<A::SignError>> {
        self.prepare().await?.send().await
    }

    pub async fn prepare(
        &self,
    ) -> Result<PreparedDeclarationV2<'a, A>, AccountError<A::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .account
                .get_nonce()
                .await
                .map_err(AccountError::Provider)?,
        };

        // Resolves max_fee
        let max_fee = match self.max_fee {
            Some(value) => value,
            None => {
                // Obtain the fee estimate
                let fee_estimate = self.estimate_fee_with_nonce(nonce).await?;
                // Convert the overall fee to little-endian bytes
                let overall_fee_bytes = fee_estimate.overall_fee.to_bytes_le();

                // Check if the remaining bytes after the first 8 are all zeros
                if overall_fee_bytes.iter().skip(8).any(|&x| x != 0) {
                    return Err(AccountError::FeeOutOfRange);
                }

                // Convert the first 8 bytes to u64
                let overall_fee_u64 =
                    u64::from_le_bytes(overall_fee_bytes[..8].try_into().unwrap());

                // Perform necessary operations on overall_fee_u64 and convert to f64 then to u64
                (((overall_fee_u64 as f64) * self.fee_estimate_multiplier) as u64).into()
            }
        };

        Ok(PreparedDeclarationV2 {
            account: self.account,
            inner: RawDeclarationV2 {
                contract_class: self.contract_class.clone(),
                compiled_class_hash: self.compiled_class_hash,
                nonce,
                max_fee,
            },
        })
    }

    async fn estimate_fee_with_nonce(
        &self,
        nonce: Felt,
    ) -> Result<FeeEstimate<Felt>, AccountError<A::SignError>> {
        let skip_signature = self.account.is_signer_interactive();
        let prepared = PreparedDeclarationV2 {
            account: self.account,
            inner: RawDeclarationV2 {
                contract_class: self.contract_class.clone(),
                compiled_class_hash: self.compiled_class_hash,
                nonce,
                max_fee: Felt::ZERO,
            },
        };

        let declare = prepared.get_declare_request(true, skip_signature).await?; // TODO: query only has to be false

        self.account
            .provider()
            .estimate_fee_single(
                BroadcastedTxn::Declare(BroadcastedDeclareTxn::QueryV2(declare)),
                vec![], // TODO: put back if needed
                self.account.block_id(),
            )
            .await
            .map_err(AccountError::Provider)
    }

    async fn simulate_with_nonce(
        &self,
        nonce: Felt,
        skip_validate: bool,
        skip_fee_charge: bool,
    ) -> Result<SimulateTransactionsResult<Felt>, AccountError<A::SignError>> {
        let skip_signature = if self.account.is_signer_interactive() {
            // If signer is interactive, we would try to minimize signing requests. However, if the
            // caller has decided to not skip validation, it's best we still request a real
            // signature, as otherwise the simulation would most likely fail.
            skip_validate
        } else {
            // Signing with non-interactive signers is cheap so always request signatures.
            false
        };

        let prepared = PreparedDeclarationV2 {
            account: self.account,
            inner: RawDeclarationV2 {
                contract_class: self.contract_class.clone(),
                compiled_class_hash: self.compiled_class_hash,
                nonce,
                max_fee: self.max_fee.unwrap_or_default(),
            },
        };
        let declare = prepared.get_declare_request(true, skip_signature).await?;

        let mut flags = vec![];

        if !skip_validate {
            flags.push(SimulationFlag::Validate);
        }
        if !skip_fee_charge {
            flags.push(SimulationFlag::FeeCharge);
        }

        self.account
            .provider()
            .simulate_transaction(
                self.account.block_id(),
                BroadcastedTxn::Declare(BroadcastedDeclareTxn::V2(declare)),
                flags,
            )
            .await
            .map_err(AccountError::Provider)
    }
}

impl<'a, A> DeclarationV3<'a, A> {
    pub fn new(
        contract_class: ContractClass<Felt>,
        compiled_class_hash: Felt,
        account: &'a A,
    ) -> Self {
        Self {
            account,
            contract_class,
            compiled_class_hash,
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

    /// Calling this function after manually specifying `nonce`, `gas` and `gas_price` turns
    /// [DeclarationV3] into [PreparedDeclarationV3]. Returns `Err` if any field is `None`.
    pub fn prepared(self) -> Result<PreparedDeclarationV3<'a, A>, NotPreparedError> {
        let nonce = self.nonce.ok_or(NotPreparedError)?;
        let gas = self.gas.ok_or(NotPreparedError)?;
        let gas_price = self.gas_price.ok_or(NotPreparedError)?;

        Ok(PreparedDeclarationV3 {
            account: self.account,
            inner: RawDeclarationV3 {
                contract_class: self.contract_class,
                compiled_class_hash: self.compiled_class_hash,
                nonce,
                gas,
                gas_price,
            },
        })
    }
}

impl<'a, A> DeclarationV3<'a, A>
where
    A: ConnectedAccount + Sync,
{
    pub async fn estimate_fee(&self) -> Result<FeeEstimate<Felt>, AccountError<A::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .account
                .get_nonce()
                .await
                .map_err(AccountError::Provider)?,
        };

        self.estimate_fee_with_nonce(nonce).await
    }

    pub async fn estimate_fee_skip_signature(
        &self,
    ) -> Result<FeeEstimate<Felt>, AccountError<A::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .account
                .get_nonce()
                .await
                .map_err(AccountError::Provider)?,
        };

        self.estimate_fee_with_nonce_skip_signature(nonce).await
    }

    pub async fn simulate(
        &self,
        skip_validate: bool,
        skip_fee_charge: bool,
    ) -> Result<SimulateTransactionsResult<Felt>, AccountError<A::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .account
                .get_nonce()
                .await
                .map_err(AccountError::Provider)?,
        };

        self.simulate_with_nonce(nonce, skip_validate, skip_fee_charge)
            .await
    }

    pub async fn send(&self) -> Result<ClassAndTxnHash<Felt>, AccountError<A::SignError>> {
        self.prepare().await?.send().await
    }

    pub async fn prepare(
        &self,
    ) -> Result<PreparedDeclarationV3<'a, A>, AccountError<A::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .account
                .get_nonce()
                .await
                .map_err(AccountError::Provider)?,
        };

        // Resolves fee settings
        let (gas, gas_price) = match (self.gas, self.gas_price) {
            (Some(gas), Some(gas_price)) => (gas, gas_price),
            (Some(gas), _) => {
                // When `gas` is specified, we only need the L1 gas price in FRI. By specifying a
                // a `gas` value, the user might be trying to avoid a full fee estimation (e.g.
                // flaky dependencies), so it's in appropriate to call `estimate_fee` here.

                let block_result = self
                    .account
                    .provider()
                    .get_block_with_tx_hashes(self.account.block_id())
                    .await
                    .map_err(AccountError::Provider)?;

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
                    return Err(AccountError::FeeOutOfRange);
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
                            return Err(AccountError::FeeOutOfRange);
                        }
                        let overall_fee =
                            u64::from_le_bytes(overall_fee_bytes[..8].try_into().unwrap());

                        let gas_price_bytes = fee_estimate.gas_price.to_bytes_le();
                        if gas_price_bytes.iter().skip(8).any(|&x| x != 0) {
                            return Err(AccountError::FeeOutOfRange);
                        }
                        let gas_price =
                            u64::from_le_bytes(gas_price_bytes[..8].try_into().unwrap());

                        (((overall_fee + gas_price - 1) / gas_price) as f64
                            * self.gas_estimate_multiplier) as u64
                    }
                };

                let gas_price = match self.gas_price {
                    Some(gas_price) => gas_price,
                    None => {
                        let gas_price_bytes = fee_estimate.gas_price.to_bytes_le();
                        if gas_price_bytes.iter().skip(8).any(|&x| x != 0) {
                            return Err(AccountError::FeeOutOfRange);
                        }
                        let gas_price =
                            u64::from_le_bytes(gas_price_bytes[..8].try_into().unwrap());

                        ((gas_price as f64) * self.gas_price_estimate_multiplier) as u128
                    }
                };

                (gas, gas_price)
            }
        };

        Ok(PreparedDeclarationV3 {
            account: self.account,
            inner: RawDeclarationV3 {
                contract_class: self.contract_class.clone(),
                compiled_class_hash: self.compiled_class_hash,
                nonce,
                gas,
                gas_price,
            },
        })
    }

    async fn estimate_fee_with_nonce(
        &self,
        nonce: Felt,
    ) -> Result<FeeEstimate<Felt>, AccountError<A::SignError>> {
        let skip_signature = self.account.is_signer_interactive();
        let prepared = PreparedDeclarationV3 {
            account: self.account,
            inner: RawDeclarationV3 {
                contract_class: self.contract_class.clone(),
                compiled_class_hash: self.compiled_class_hash,
                nonce,
                gas: 0,
                gas_price: 0,
            },
        };

        let declare = prepared.get_declare_request(true, skip_signature).await?;

        let result = self
            .account
            .provider()
            .estimate_fee_single(
                BroadcastedTxn::Declare(BroadcastedDeclareTxn::V3(declare)),
                if skip_signature {
                    // Validation would fail since real signature was not requested
                    vec!["SKIP_VALIDATE".to_string()]
                } else {
                    // With the correct signature in place, run validation for accurate results
                    vec![]
                },
                self.account.block_id(),
            )
            .await;

        match result {
            Ok(fee_estimate) => Ok(fee_estimate),
            Err(e) => Err(AccountError::Provider(e)),
        }
    }

    async fn estimate_fee_with_nonce_skip_signature(
        &self,
        nonce: Felt,
    ) -> Result<FeeEstimate<Felt>, AccountError<A::SignError>> {
        let skip_signature = true;
        let prepared = PreparedDeclarationV3 {
            account: self.account,
            inner: RawDeclarationV3 {
                contract_class: self.contract_class.clone(),
                compiled_class_hash: self.compiled_class_hash,
                nonce,
                gas: 0,
                gas_price: 0,
            },
        };

        let declare = prepared.get_declare_request(true, skip_signature).await?;

        let result = self
            .account
            .provider()
            .estimate_fee_single(
                BroadcastedTxn::Declare(BroadcastedDeclareTxn::V3(declare)),
                if skip_signature {
                    // Validation would fail since real signature was not requested
                    vec!["SKIP_VALIDATE".to_string()]
                } else {
                    // With the correct signature in place, run validation for accurate results
                    vec![]
                },
                self.account.block_id(),
            )
            .await;

        match result {
            Ok(fee_estimate) => Ok(fee_estimate),
            Err(e) => Err(AccountError::Provider(e)),
        }
    }

    async fn simulate_with_nonce(
        &self,
        nonce: Felt,
        skip_validate: bool,
        skip_fee_charge: bool,
    ) -> Result<SimulateTransactionsResult<Felt>, AccountError<A::SignError>> {
        let skip_signature = if self.account.is_signer_interactive() {
            // If signer is interactive, we would try to minimize signing requests. However, if the
            // caller has decided to not skip validation, it's best we still request a real
            // signature, as otherwise the simulation would most likely fail.
            skip_validate
        } else {
            // Signing with non-interactive signers is cheap so always request signatures.
            false
        };

        let prepared = PreparedDeclarationV3 {
            account: self.account,
            inner: RawDeclarationV3 {
                contract_class: self.contract_class.clone(),
                compiled_class_hash: self.compiled_class_hash,
                nonce,
                gas: self.gas.unwrap_or_default(),
                gas_price: self.gas_price.unwrap_or_default(),
            },
        };
        let declare = prepared.get_declare_request(true, skip_signature).await?;

        let mut flags = vec![];

        if skip_validate {
            flags.push(SimulationFlag::Validate);
        }
        if skip_fee_charge {
            flags.push(SimulationFlag::FeeCharge);
        }

        self.account
            .provider()
            .simulate_transaction(
                self.account.block_id(),
                BroadcastedTxn::Declare(BroadcastedDeclareTxn::V3(declare)),
                flags,
            )
            .await
            .map_err(AccountError::Provider)
    }
}

impl RawDeclarationV2 {
    pub fn transaction_hash(&self, chain_id: Felt, address: Felt, query_only: bool) -> Felt {
        compute_hash_on_elements(&[
            PREFIX_DECLARE,
            if query_only {
                QUERY_VERSION_TWO
            } else {
                Felt::TWO
            }, // version
            address,
            Felt::ZERO, // entry_point_selector
            compute_hash_on_elements(&[self.contract_class.class_hash()]),
            self.max_fee,
            chain_id,
            self.nonce,
            self.compiled_class_hash,
        ])
    }

    pub fn contract_class(&self) -> &ContractClass<Felt> {
        &self.contract_class
    }

    pub fn compiled_class_hash(&self) -> Felt {
        self.compiled_class_hash
    }

    pub fn nonce(&self) -> Felt {
        self.nonce
    }

    pub fn max_fee(&self) -> Felt {
        self.max_fee
    }
}

impl RawDeclarationV3 {
    pub fn transaction_hash(&self, chain_id: Felt, address: Felt, _query_only: bool) -> Felt {
        // Main data vector to collect all elements for hashing
        let mut data = vec![PREFIX_DECLARE, Felt::THREE, address];

        // Fee data collection
        let mut fee_data = vec![Felt::ZERO]; // Hard-coded fee market

        // First L1 gas resource buffer
        let mut resource_buffer = [
            0, 0, b'L', b'1', b'_', b'G', b'A', b'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        resource_buffer[8..(8 + 8)].copy_from_slice(&self.gas.to_be_bytes());
        resource_buffer[(8 + 8)..].copy_from_slice(&self.gas_price.to_be_bytes());
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
        data.push(chain_id);
        data.push(self.nonce);
        data.push(Felt::ZERO); // Hard-coded L1 DA mode for nonce and fee

        // Hard-coded empty `account_deployment_data`
        data.push(Poseidon::hash_array(&[]));

        // Contract class and compiled class hashes
        data.push(self.contract_class.class_hash());
        data.push(self.compiled_class_hash);

        // Final hash computation
        Poseidon::hash_array(&data)
    }

    pub fn contract_class(&self) -> &ContractClass<Felt> {
        &self.contract_class
    }

    pub fn compiled_class_hash(&self) -> Felt {
        self.compiled_class_hash
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

impl<'a, A> PreparedDeclarationV2<'a, A>
where
    A: Account,
{
    /// Locally calculates the hash of the transaction to be sent from this declaration given the
    /// parameters.
    pub fn transaction_hash(&self, query_only: bool) -> Felt {
        self.inner
            .transaction_hash(self.account.chain_id(), self.account.address(), query_only)
    }
}

impl<'a, A> PreparedDeclarationV2<'a, A>
where
    A: ConnectedAccount,
{
    pub async fn send(&self) -> Result<ClassAndTxnHash<Felt>, AccountError<A::SignError>> {
        let tx_request = self.get_declare_request(false, false).await?;

        self.account
            .provider()
            .add_declare_transaction(BroadcastedTxn::Declare(BroadcastedDeclareTxn::V2(
                tx_request,
            )))
            .await
            .map_err(AccountError::Provider)
    }

    pub async fn send_from_request(
        &self,
        tx_request: BroadcastedDeclareTxnV2<Felt>,
    ) -> Result<ClassAndTxnHash<Felt>, AccountError<A::SignError>> {
        self.account
            .provider()
            .add_declare_transaction(BroadcastedTxn::Declare(BroadcastedDeclareTxn::V2(
                tx_request,
            )))
            .await
            .map_err(AccountError::Provider)
    }

    pub async fn get_declare_request(
        &self,
        query_only: bool,
        skip_signature: bool,
    ) -> Result<BroadcastedDeclareTxnV2<Felt>, AccountError<A::SignError>> {
        let signature = if skip_signature {
            vec![]
        } else {
            self.account
                .sign_declaration_v2(&self.inner, query_only)
                .await
                .map_err(AccountError::Signing)?
        };

        Ok(BroadcastedDeclareTxnV2 {
            max_fee: self.inner.max_fee,
            signature,
            nonce: self.inner.nonce,
            contract_class: Arc::clone(&self.inner.contract_class).as_ref().clone(),
            compiled_class_hash: self.inner.compiled_class_hash,
            sender_address: self.account.address(),
        })
    }

    pub async fn get_raw_execution(&self) -> &RawDeclarationV2 {
        &self.inner
    }
}

impl<'a, A> PreparedDeclarationV3<'a, A>
where
    A: Account,
{
    /// Locally calculates the hash of the transaction to be sent from this declaration given the
    /// parameters.
    pub fn transaction_hash(&self, query_only: bool) -> Felt {
        self.inner
            .transaction_hash(self.account.chain_id(), self.account.address(), query_only)
    }
}

impl<'a, A> PreparedDeclarationV3<'a, A>
where
    A: ConnectedAccount,
{
    pub async fn send(&self) -> Result<ClassAndTxnHash<Felt>, AccountError<A::SignError>> {
        let tx_request = self.get_declare_request(false, false).await?;
        self.account
            .provider()
            .add_declare_transaction(BroadcastedTxn::Declare(BroadcastedDeclareTxn::V3(
                tx_request,
            )))
            .await
            .map_err(AccountError::Provider)
    }

    pub async fn send_from_request(
        &self,
        tx_request: BroadcastedDeclareTxnV3<Felt>,
    ) -> Result<ClassAndTxnHash<Felt>, AccountError<A::SignError>> {
        self.account
            .provider()
            .add_declare_transaction(BroadcastedTxn::Declare(BroadcastedDeclareTxn::V3(
                tx_request,
            )))
            .await
            .map_err(AccountError::Provider)
    }

    pub async fn get_declare_request(
        &self,
        query_only: bool,
        skip_signature: bool,
    ) -> Result<BroadcastedDeclareTxnV3<Felt>, AccountError<A::SignError>> {
        Ok(BroadcastedDeclareTxnV3 {
            sender_address: self.account.address(),
            compiled_class_hash: self.inner.compiled_class_hash,
            signature: if skip_signature {
                vec![]
            } else {
                self.account
                    .sign_declaration_v3(&self.inner, query_only)
                    .await
                    .map_err(AccountError::Signing)?
            },
            nonce: self.inner.nonce,
            contract_class: self.inner.contract_class.clone(),
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
            tip: Felt::from(0),
            // Hard-coded empty `paymaster_data`
            paymaster_data: vec![],
            // Hard-coded empty `account_deployment_data`
            account_deployment_data: vec![],
            // Hard-coded L1 DA mode for nonce and fee
            nonce_data_availability_mode: DaMode::L1,
            fee_data_availability_mode: DaMode::L1,
        })
    }

    pub async fn get_raw_execution(&self) -> &RawDeclarationV3 {
        &self.inner
    }
}
