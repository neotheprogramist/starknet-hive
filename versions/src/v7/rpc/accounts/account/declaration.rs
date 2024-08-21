use crate::v7::rpc::accounts::account::ContractClassHasher;
use crate::v7::rpc::accounts::factory::DataAvailabilityMode;
use crate::v7::rpc::{accounts::errors::NotPreparedError, providers::provider::Provider};
use std::error::Error; 

use starknet_types_core::curve::compute_hash_on_elements;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{poseidon_hash_many, PoseidonHasher};
use starknet_types_rpc::v0_7_1::{
    BroadcastedDeclareTxn, BroadcastedDeclareTxnV2, BroadcastedDeclareTxnV3, BroadcastedTxn,
    ClassAndTxnHash, ContractClass, FeeEstimate, SimulateTransactionsResult, SimulationFlag,
    SimulationFlagForEstimateFee,
};
use starknet_types_rpc::{
    DaMode, MaybePendingBlockWithTxHashes, Resource, ResourceBounds, ResourceBoundsMapping
};
use tracing::{debug, info};
use tracing::error;
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

/// 2 ^ 128 + 1
const QUERY_VERSION_ONE: Felt = Felt::from_raw([
    576460752142433776,
    18446744073709551584,
    17407,
    18446744073700081633,
]);

/// 2 ^ 128 + 2
const QUERY_VERSION_TWO: Felt = Felt::from_raw([
    576460752142433232,
    18446744073709551584,
    17407,
    18446744073700081601,
]);

/// 2 ^ 128 + 3
const QUERY_VERSION_THREE: Felt = Felt::from_raw([
    576460752142432688,
    18446744073709551584,
    17407,
    18446744073700081569,
]);

const DATA_AVAILABILITY_MODE_BITS: u8 = 32;

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

    async fn prepare(&self) -> Result<PreparedDeclarationV2<'a, A>, AccountError<A::SignError>> {
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

    async fn prepare(&self) -> Result<PreparedDeclarationV3<'a, A>, AccountError<A::SignError>> {
        // Resolves nonce
        info!("Before nonce");
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .account
                .get_nonce()
                .await
                .map_err(AccountError::Provider)?,
        };
        info!("After nonce");
        info!("Before gas and gas_price");
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
                info!("test gas1");
                let fee_estimate = self.estimate_fee_with_nonce(nonce).await?;
                info!("test gas2");

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
        // let gas = self.gas.unwrap_or_default();
        // let gas_price = self.gas_price.unwrap_or_default();

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
        info!("Before account");

        let result = self.account
        .provider()
        .estimate_fee_single(
            BroadcastedTxn::Declare(BroadcastedDeclareTxn::V3(declare)),
            if skip_signature {
                // Validation would fail since real signature was not requested
                vec![]
            } else {
                // With the correct signature in place, run validation for accurate results
                vec![]
            },
            self.account.block_id(),
        )
        .await;
    
    match result {
        Ok(fee_estimate) => {
            // Log the successful result
            info!("Fee estimation succeeded: {:?}", fee_estimate);
            Ok(fee_estimate) // Return the result or handle it as needed
        },
        Err(e) => {
            // Log the error
            error!("Fee estimation failed: {:?}", e);
            Err(AccountError::Provider(e))
        },
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

// impl<'a, A> LegacyDeclaration<'a, A> {
//     pub fn new(contract_class: Arc<DeprecatedContractClass>, account: &'a A) -> Self {
//         Self {
//             account,
//             contract_class,
//             nonce: None,
//             max_fee: None,
//             fee_estimate_multiplier: 1.1,
//         }
//     }

//     pub fn nonce(self, nonce: Felt) -> Self {
//         Self {
//             nonce: Some(nonce),
//             ..self
//         }
//     }

//     pub fn max_fee(self, max_fee: Felt) -> Self {
//         Self {
//             max_fee: Some(max_fee),
//             ..self
//         }
//     }

//     pub fn fee_estimate_multiplier(self, fee_estimate_multiplier: f64) -> Self {
//         Self {
//             fee_estimate_multiplier,
//             ..self
//         }
//     }

//     /// Calling this function after manually specifying `nonce` and `max_fee` turns
//     /// [LegacyDeclaration] into [PreparedLegacyDeclaration]. Returns `Err` if either field is
//     /// `None`.
//     pub fn prepared(self) -> Result<PreparedLegacyDeclaration<'a, A>, NotPreparedError> {
//         let nonce = self.nonce.ok_or(NotPreparedError)?;
//         let max_fee = self.max_fee.ok_or(NotPreparedError)?;

//         Ok(PreparedLegacyDeclaration {
//             account: self.account,
//             inner: RawLegacyDeclaration {
//                 contract_class: self.contract_class,
//                 nonce,
//                 max_fee,
//             },
//         })
//     }
// }

// impl<'a, A> LegacyDeclaration<'a, A>
// where
//     A: ConnectedAccount + Sync,
// {
//     pub async fn estimate_fee(&self) -> Result<FeeEstimate, AccountError<A::SignError>> {
//         // Resolves nonce
//         let nonce = match self.nonce {
//             Some(value) => value,
//             None => self
//                 .account
//                 .get_nonce()
//                 .await
//                 .map_err(AccountError::Provider)?,
//         };

//         self.estimate_fee_with_nonce(nonce).await
//     }

//     pub async fn simulate(
//         &self,
//         skip_validate: bool,
//         skip_fee_charge: bool,
//     ) -> Result<SimulateTransactionsResult, AccountError<A::SignError>> {
//         // Resolves nonce
//         let nonce = match self.nonce {
//             Some(value) => value,
//             None => self
//                 .account
//                 .get_nonce()
//                 .await
//                 .map_err(AccountError::Provider)?,
//         };

//         self.simulate_with_nonce(nonce, skip_validate, skip_fee_charge)
//             .await
//     }

//     pub async fn send(&self) -> Result<ClassAndTxnHash, AccountError<A::SignError>> {
//         self.prepare().await?.send().await
//     }

//     async fn prepare(
//         &self,
//     ) -> Result<PreparedLegacyDeclaration<'a, A>, AccountError<A::SignError>> {
//         // Resolves nonce
//         let nonce = match self.nonce {
//             Some(value) => value,
//             None => self
//                 .account
//                 .get_nonce()
//                 .await
//                 .map_err(AccountError::Provider)?,
//         };

//         // Resolves max_fee
//         let max_fee = match self.max_fee {
//             Some(value) => value,
//             None => {
//                 // Obtain the fee estimate
//                 let fee_estimate = self.estimate_fee_with_nonce(nonce).await?;
//                 // Convert the overall fee to little-endian bytes
//                 let overall_fee_bytes = fee_estimate.overall_fee.to_le_bytes();

//                 // Check if the remaining bytes after the first 8 are all zeros
//                 if overall_fee_bytes.iter().skip(8).any(|&x| x != 0) {
//                     return Err(AccountError::FeeOutOfRange);
//                 }

//                 // Convert the first 8 bytes to u64
//                 let overall_fee_u64 =
//                     u64::from_le_bytes(overall_fee_bytes[..8].try_into().unwrap());

//                 // Perform necessary operations on overall_fee_u64 and convert to f64 then to u64
//                 (((overall_fee_u64 as f64) * self.fee_estimate_multiplier) as u64).into()
//             }
//         };

//         Ok(PreparedLegacyDeclaration {
//             account: self.account,
//             inner: RawLegacyDeclaration {
//                 contract_class: self.contract_class.clone(),
//                 nonce,
//                 max_fee,
//             },
//         })
//     }

//     async fn estimate_fee_with_nonce(
//         &self,
//         nonce: Felt,
//     ) -> Result<FeeEstimate, AccountError<A::SignError>> {
//         let skip_signature = self.account.is_signer_interactive();

//         let prepared = PreparedLegacyDeclaration {
//             account: self.account,
//             inner: RawLegacyDeclaration {
//                 contract_class: self.contract_class.clone(),
//                 nonce,
//                 max_fee: Felt::ZERO,
//             },
//         };
//         let declare = prepared.get_declare_request(true, skip_signature).await?;

//         self.account
//             .provider()
//             .estimate_fee_single(
//                 BroadcastedTxn::Declare(BroadcastedDeclareTxn::V1(declare)),
//                 self.account.block_id(),
//             )
//             .await
//             .map_err(AccountError::Provider)
//     }

//     async fn simulate_with_nonce(
//         &self,
//         nonce: Felt,
//         skip_validate: bool,
//         skip_fee_charge: bool,
//     ) -> Result<SimulateTransactionsResult, AccountError<A::SignError>> {
//         let skip_signature = if self.account.is_signer_interactive() {
//             // If signer is interactive, we would try to minimize signing requests. However, if the
//             // caller has decided to not skip validation, it's best we still request a real
//             // signature, as otherwise the simulation would most likely fail.
//             skip_validate
//         } else {
//             // Signing with non-interactive signers is cheap so always request signatures.
//             false
//         };

//         let prepared = PreparedLegacyDeclaration {
//             account: self.account,
//             inner: RawLegacyDeclaration {
//                 contract_class: self.contract_class.clone(),
//                 nonce,
//                 max_fee: self.max_fee.unwrap_or_default(),
//             },
//         };
//         let declare = prepared.get_declare_request(true, skip_signature).await?;

//         let mut flags = vec![];

//         if !skip_validate {
//             flags.push(SimulationFlag::Validate);
//         }
//         if !skip_fee_charge {
//             flags.push(SimulationFlag::FeeCharge);
//         }

//         self.account
//             .provider()
//             .simulate_transaction(
//                 self.account.block_id(),
//                 BroadcastedTxn::Declare(BroadcastedDeclareTxn::V1(declare)),
//                 flags,
//             )
//             .await
//             .map_err(AccountError::Provider)
//     }
// }

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
    // pub fn calculate_transaction_hash(
    //     &self, chain_id: Felt, address: Felt, query_only: bool) -> Result<Felt, Box<dyn Error>> {
    //     let common_fields =
    //         Self::common_fields_for_hash(&self,PREFIX_DECLARE, chain_id, address)?;
    //     println!("common_fields {:?}", common_fields);
    //     let account_deployment_data_hash = poseidon_hash_many(&self.account_deployment_data);
    
    //     let fields_to_hash = [
    //         common_fields.as_slice(),
    //         &[account_deployment_data_hash],
    //         &[self.contract_class.class_hash()],
    //         &[self.compiled_class_hash],
    //     ]
    //     .concat();
    
    //     let txn_hash = poseidon_hash_many(fields_to_hash.as_slice());
    //     Ok(txn_hash)
    // }
    
    // /// Returns the array of Felts that reflects (tip, resource_bounds_for_fee) from SNIP-8
    // fn get_resource_bounds_array(txn: &BroadcastedDeclareTxnV3<Felt>) -> Result<Vec<Felt>, Box<dyn Error>> {
    //     let mut array = Vec::<Felt>::new();
    //     array.push(txn.tip);
    
    //     array.push(Self::field_element_from_resource_bounds(
    //         Resource::L1Gas,
    //         &txn.resource_bounds.l1_gas,
    //     )?);
    //     array.push(Self::field_element_from_resource_bounds(
    //         Resource::L2Gas,
    //         &txn.resource_bounds.l2_gas,
    //     )?);
    //     println!("{:?}", array);
    
    //     Ok(array)
    // }
    
    // fn field_element_from_resource_bounds(
    //     resource: Resource,
    //     resource_bounds: &ResourceBounds,
    // ) -> Result<Felt, Box<dyn Error>> {
    //     let resource_name_as_json_string =
    //         serde_json::to_value(resource)?;
    
    //     // Ensure it's a string and get bytes
    //     let resource_name_bytes = resource_name_as_json_string
    //         .as_str()
    //         .ok_or("Resource name is not a string")? 
    //         .as_bytes();
    //     println!("0 {:?}", resource_name_bytes);
        
    //     let max_amount_hex_str = resource_bounds.max_amount.as_str().trim_start_matches( "0x");
    //     let max_amount_u64 = u64::from_str_radix(max_amount_hex_str, 16)?;
    
    //     let max_price_per_unit_hex_str = resource_bounds.max_price_per_unit.as_str().trim_start_matches( "0x");
    //     let max_price_per_unit_u64 = u128::from_str_radix(max_price_per_unit_hex_str, 16)?;
    
    
    //     // println!("1 {}", max_amount_u64);
    //     // println!("2 {}", max_price_per_unit_u64);
    //     // (resource||max_amount||max_price_per_unit) from SNIP-8 https://github.com/starknet-io/SNIPs/blob/main/SNIPS/snip-8.md#protocol-changes
    //     let bytes: Vec<u8> = [
    //         resource_name_bytes,
    //         max_amount_u64.to_be_bytes().as_slice(),
    //         max_price_per_unit_u64.to_be_bytes().as_slice(),
    //     ]
    //     .into_iter()
    //     .flatten()
    //     .copied()
    //     .collect();
    
    //     Ok(Felt::from_bytes_be_slice(&bytes))
    // }
    
    // fn common_fields_for_hash(
    //     &self,
    //     tx_prefix: Felt,
    //     chain_id: Felt,
    //     sender: Felt,
    //     txn: &BroadcastedDeclareTxnV3<Felt>,
    // ) -> Result<Vec<Felt>, Box<dyn Error>> {
    //     // println!("get_resource_bounds_array {:?}", Self::get_resource_bounds_array(txn)?);
    //     // println!("get_data_availability_modes_field_element {:?}", Self::get_data_availability_modes_field_element(txn));
    //     let array: Vec<Felt> = vec![
    //         tx_prefix,                                                   // TX_PREFIX
    //         Felt::THREE,                                                     // version
    //         sender,                                                     // address
    //         // poseidon_hash_many(&[Felt::from_hex_unchecked("0x0"), Felt::from_hex_unchecked("0x4c315f47415300000000000186a0000000000000000000000002540be400"),Felt::from_hex_unchecked("0x4c325f474153000000000000000000000000000000000000000000000000"), ]), /* h(tip, resource_bounds_for_fee) */
    //         poseidon_hash_many(Self::get_resource_bounds_array(txn)?.as_slice()), /* h(tip, resource_bounds_for_fee) */
    //         poseidon_hash_many(&txn.paymaster_data),                          // h(paymaster_data)
    //         chain_id,                                                    // chain_id
    //         self.nonce,                                                       // nonce
    //         Self::get_data_availability_modes_field_element(txn),                 /* nonce_data_availability ||
    //                                                                       * fee_data_availability_mode */
    //     ];
    
    //     Ok(array)
    // }
    
    // fn get_data_availability_mode_value_as_u64(
    //     data_availability_mode: DaMode,
    // ) -> u64 {
    //     match data_availability_mode {
    //         DaMode::L1 => 0,
    //         DaMode::L2 => 1,
    //     }
    // }
    
    // /// Returns Felt that encodes the data availability modes of the transaction
    // fn get_data_availability_modes_field_element(txn: &BroadcastedDeclareTxnV3<Felt>) -> Felt {
    
    
    //     let da_mode = Self::get_data_availability_mode_value_as_u64(txn.nonce_data_availability_mode.clone())
    //         << DATA_AVAILABILITY_MODE_BITS;
    //     let da_mode =
    //         da_mode + Self::get_data_availability_mode_value_as_u64(txn.fee_data_availability_mode.clone());
    //     Felt::from(da_mode)
    // }
    
    


    pub fn transaction_hash(&self, chain_id: Felt, address: Felt, query_only: bool) -> Felt {
        let mut hasher = PoseidonHasher::new();

        hasher.update(PREFIX_DECLARE);
        hasher.update(if query_only {
            Felt::THREE
        } else {
            Felt::THREE
        });
        hasher.update(address);

        hasher.update({
            let mut fee_hasher = PoseidonHasher::new();

            // Tip: fee market has not been been activated yet so it's hard-coded to be 0
            fee_hasher.update(Felt::ZERO);

            let mut resource_buffer = [
                0, 0, b'L', b'1', b'_', b'G', b'A', b'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            resource_buffer[8..(8 + 8)].copy_from_slice(&self.gas.to_be_bytes());
            resource_buffer[(8 + 8)..].copy_from_slice(&self.gas_price.to_be_bytes());
            fee_hasher.update(Felt::from_bytes_be(&resource_buffer));

            // L2 resources are hard-coded to 0
            let resource_buffer = [
                0, 0, b'L', b'2', b'_', b'G', b'A', b'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            fee_hasher.update(Felt::from_bytes_be(&resource_buffer));

            fee_hasher.finalize()
        });

        // Hard-coded empty `paymaster_data`
        hasher.update(PoseidonHasher::new().finalize());

        hasher.update(chain_id);
        hasher.update(self.nonce);

        // Hard-coded L1 DA mode for nonce and fee
        hasher.update(Felt::ZERO);

        // Hard-coded empty `account_deployment_data`
        hasher.update(PoseidonHasher::new().finalize());

        hasher.update(self.contract_class.class_hash());
        hasher.update(self.compiled_class_hash);

        hasher.finalize()
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

// impl RawLegacyDeclaration {
//     pub fn transaction_hash(
//         &self,
//         chain_id: Felt,
//         address: Felt,
//         query_only: bool,
//     ) -> Result<Felt, ComputeClassHashError> {
//         Ok(compute_hash_on_elements(&[
//             PREFIX_DECLARE,
//             if query_only {
//                 QUERY_VERSION_ONE
//             } else {
//                 Felt::ONE
//             }, // version
//             address,
//             Felt::ZERO, // entry_point_selector
//             compute_hash_on_elements(&[self.contract_class.class_hash()?]),
//             self.max_fee,
//             chain_id,
//             self.nonce,
//         ]))
//     }

//     pub fn contract_class(&self) -> &DeprecatedContractClass {
//         &self.contract_class
//     }

//     pub fn nonce(&self) -> Felt {
//         self.nonce
//     }

//     pub fn max_fee(&self) -> Felt {
//         self.max_fee
//     }
// }

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
            .add_declare_transaction(BroadcastedDeclareTxn::V2(tx_request))
            .await
            .map_err(AccountError::Provider)
    }

    async fn get_declare_request(
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
            type_: Some("DECLARE".to_string()),
        })
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
            .add_declare_transaction(BroadcastedDeclareTxn::V3(tx_request))
            .await
            .map_err(AccountError::Provider)
    }

    async fn get_declare_request(
        &self,
        query_only: bool,
        skip_signature: bool,
    ) -> Result<BroadcastedDeclareTxnV3<Felt>, AccountError<A::SignError>> {
        Ok(BroadcastedDeclareTxnV3 {
            // transaction_hash: self.transaction_hash(query_only),
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
                    max_amount: Felt::from_dec_str(&self.inner.gas.to_string()).unwrap().to_hex_string(),        
                    max_price_per_unit: Felt::from_dec_str(&self.inner.gas_price.to_string()).unwrap().to_hex_string(),
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
            // is_query: query_only,
            type_: Some("DECLARE".to_string()),
            // version: Felt::THREE,
        })
    }
}

// impl<'a, A> PreparedLegacyDeclaration<'a, A>
// where
//     A: Account,
// {
//     /// Locally calculates the hash of the transaction to be sent from this declaration given the
//     /// parameters.
//     pub fn transaction_hash(&self, query_only: bool) -> Result<Felt, ComputeClassHashError> {
//         self.inner
//             .transaction_hash(self.account.chain_id(), self.account.address(), query_only)
//     }
// }

// impl<'a, A> PreparedLegacyDeclaration<'a, A>
// where
//     A: ConnectedAccount,
// {
//     pub async fn send(&self) -> Result<ClassAndTxnHash, AccountError<A::SignError>> {
//         let tx_request = self.get_declare_request(false, false).await?;
//         self.account
//             .provider()
//             .add_declare_transaction(BroadcastedDeclareTxn::V1(tx_request))
//             .await
//             .map_err(AccountError::Provider)
//     }

//     async fn get_declare_request(
//         &self,
//         query_only: bool,
//         skip_signature: bool,
//     ) -> Result<BroadcastedDeclareTxnV1, AccountError<A::SignError>> {
//         let compressed_class = Arc::as_ref(&self.inner.contract_class).clone();

//         Ok(BroadcastedDeclareTxnV1 {
//             max_fee: self.inner.max_fee,
//             signature: if skip_signature {
//                 vec![]
//             } else {
//                 self.account
//                     .sign_legacy_declaration(&self.inner, query_only)
//                     .await
//                     .map_err(AccountError::Signing)?
//             },
//             nonce: self.inner.nonce,
//             contract_class: compressed_class,
//             sender_address: self.account.address(),
//         })
//     }
// }
