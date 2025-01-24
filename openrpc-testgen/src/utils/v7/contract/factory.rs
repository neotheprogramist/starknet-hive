use starknet_types_core::felt::Felt;
use starknet_types_rpc::v0_7_1::{
    AddInvokeTransactionResult, FeeEstimate, SimulateTransactionsResult,
};

use crate::utils::v7::accounts::{
    account::{
        Account, AccountError, ConnectedAccount, ExecutionV1, ExecutionV3, PreparedExecutionV1,
        PreparedExecutionV3,
    },
    call::Call,
};

use super::helpers::{get_udc_deployed_address, UdcUniqueSettings, UdcUniqueness};

// use crate::{
//     account::{call::Call, Account, AccountError, ConnectedAccount, ExecutionV1, ExecutionV3},
//     codegen::{FeeEstimate, SimulatedTransaction},
//     models::InvokeTransactionResult,
//     starknet_utils::{get_udc_deployed_address, UdcUniqueSettings, UdcUniqueness},
// };

/// The default UDC address: 0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf.
const UDC_ADDRESS: Felt = Felt::from_raw([
    121672436446604875,
    9333317513348225193,
    15685625669053253235,
    15144800532519055890,
]);
/// Selector for entrypoint `deployContract`.
const SELECTOR_DEPLOYCONTRACT: Felt = Felt::from_raw([
    469988280392664069,
    1439621915307882061,
    1265649739554438882,
    18249998464715511309,
]);

pub struct ContractFactory<A> {
    class_hash: Felt,
    udc_address: Felt,
    account: A,
}

/// Abstraction over contract deployment via the UDC. This type uses `INVOKE` v1 transactions under
/// the hood, and hence pays transaction fees in ETH. To use v3 transactions for STRK fee payment,
/// use [DeploymentV3] instead.
#[must_use]
pub struct DeploymentV1<'f, A> {
    factory: &'f ContractFactory<A>,
    constructor_calldata: Vec<Felt>,
    salt: Felt,
    unique: bool,
    // The following fields allow us to mimic an `Execution` API.
    nonce: Option<Felt>,
    max_fee: Option<Felt>,
    fee_estimate_multiplier: f64,
}

/// Abstraction over contract deployment via the UDC. This type uses `INVOKE` v3 transactions under
/// the hood, and hence pays transaction fees in STRK. To use v1 transactions for ETH fee payment,
/// use [DeploymentV1] instead.
#[must_use]
pub struct DeploymentV3<'f, A> {
    factory: &'f ContractFactory<A>,
    constructor_calldata: Vec<Felt>,
    salt: Felt,
    unique: bool,
    // The following fields allow us to mimic an `Execution` API.
    nonce: Option<Felt>,
    gas: Option<u64>,
    gas_price: Option<u128>,
    gas_estimate_multiplier: f64,
    gas_price_estimate_multiplier: f64,
}

impl<A> ContractFactory<A> {
    pub fn new(class_hash: Felt, account: A) -> Self {
        Self::new_with_udc(class_hash, account, UDC_ADDRESS)
    }

    pub fn new_with_udc(class_hash: Felt, account: A, udc_address: Felt) -> Self {
        Self {
            class_hash,
            udc_address,
            account,
        }
    }
}

impl<A> ContractFactory<A>
where
    A: Account,
{
    pub fn deploy_v1(
        &self,
        constructor_calldata: Vec<Felt>,
        salt: Felt,
        unique: bool,
    ) -> DeploymentV1<A> {
        DeploymentV1 {
            factory: self,
            constructor_calldata,
            salt,
            unique,
            nonce: None,
            max_fee: None,
            fee_estimate_multiplier: 1.1,
        }
    }

    pub fn deploy_v3(
        &self,
        constructor_calldata: Vec<Felt>,
        salt: Felt,
        unique: bool,
    ) -> DeploymentV3<A> {
        DeploymentV3 {
            factory: self,
            constructor_calldata,
            salt,
            unique,
            nonce: None,
            gas: None,
            gas_price: None,
            gas_estimate_multiplier: 1.5,
            gas_price_estimate_multiplier: 1.5,
        }
    }

    #[deprecated = "use version specific variants (`deploy_v1` & `deploy_v3`) instead"]
    pub fn deploy(
        &self,
        constructor_calldata: Vec<Felt>,
        salt: Felt,
        unique: bool,
    ) -> DeploymentV3<A> {
        self.deploy_v3(constructor_calldata, salt, unique)
    }
}

impl<'f, A> DeploymentV1<'f, A> {
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
}

impl<'f, A> DeploymentV3<'f, A> {
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
}

impl<'f, A> DeploymentV1<'f, A>
where
    A: Account,
{
    /// Calculate the resulting contract address without sending a transaction.
    pub fn deployed_address(&self) -> Felt {
        get_udc_deployed_address(
            self.salt,
            self.factory.class_hash,
            &if self.unique {
                UdcUniqueness::Unique(UdcUniqueSettings {
                    deployer_address: self.factory.account.address(),
                    udc_contract_address: self.factory.udc_address,
                })
            } else {
                UdcUniqueness::NotUnique
            },
            &self.constructor_calldata,
        )
    }
}

impl<'f, A> DeploymentV3<'f, A>
where
    A: Account,
{
    /// Calculate the resulting contract address without sending a transaction.
    pub fn deployed_address(&self) -> Felt {
        get_udc_deployed_address(
            self.salt,
            self.factory.class_hash,
            &if self.unique {
                UdcUniqueness::Unique(UdcUniqueSettings {
                    deployer_address: self.factory.account.address(),
                    udc_contract_address: self.factory.udc_address,
                })
            } else {
                UdcUniqueness::NotUnique
            },
            &self.constructor_calldata,
        )
    }
}
use std::fmt::Debug;

impl<'f, A> DeploymentV1<'f, A>
where
    A: ConnectedAccount + Sync + Debug,
{
    pub async fn estimate_fee(&self) -> Result<FeeEstimate<Felt>, AccountError<A::SignError>> {
        let execution: ExecutionV1<A> = self.into();
        execution.estimate_fee().await
    }

    pub async fn simulate(
        &self,
        skip_validate: bool,
        skip_fee_charge: bool,
    ) -> Result<SimulateTransactionsResult<Felt>, AccountError<A::SignError>> {
        let execution: ExecutionV1<A> = self.into();
        execution.simulate(skip_validate, skip_fee_charge).await
    }

    pub async fn prepare_execute(
        &self,
    ) -> Result<PreparedExecutionV1<'f, A>, AccountError<A::SignError>> {
        let execution: ExecutionV1<A> = self.into();
        execution.prepare().await
    }

    pub async fn send(
        &self,
    ) -> Result<AddInvokeTransactionResult<Felt>, AccountError<A::SignError>> {
        let execution: ExecutionV1<A> = self.into();

        execution.send().await
    }
}

impl<'f, A> DeploymentV3<'f, A>
where
    A: ConnectedAccount + Sync,
{
    pub async fn estimate_fee(&self) -> Result<FeeEstimate<Felt>, AccountError<A::SignError>> {
        let execution: ExecutionV3<A> = self.into();
        execution.estimate_fee().await
    }

    pub async fn simulate(
        &self,
        skip_validate: bool,
        skip_fee_charge: bool,
    ) -> Result<SimulateTransactionsResult<Felt>, AccountError<A::SignError>> {
        let execution: ExecutionV3<A> = self.into();
        execution.simulate(skip_validate, skip_fee_charge).await
    }

    pub async fn send(
        &self,
    ) -> Result<AddInvokeTransactionResult<Felt>, AccountError<A::SignError>> {
        let execution: ExecutionV3<A> = self.into();
        execution.send().await
    }

    pub async fn prepare_execute(
        &self,
    ) -> Result<PreparedExecutionV3<'f, A>, AccountError<A::SignError>> {
        let execution: ExecutionV3<A> = self.into();
        execution.prepare().await
    }
}

impl<'f, A> From<&DeploymentV1<'f, A>> for ExecutionV1<'f, A> {
    fn from(value: &DeploymentV1<'f, A>) -> Self {
        let mut calldata = vec![
            value.factory.class_hash,
            value.salt,
            if value.unique { Felt::ONE } else { Felt::ZERO },
            value.constructor_calldata.len().into(),
        ];
        calldata.extend_from_slice(&value.constructor_calldata);

        let execution = Self::new(
            vec![Call {
                to: value.factory.udc_address,
                selector: SELECTOR_DEPLOYCONTRACT,
                calldata,
            }],
            &value.factory.account,
        );

        let execution = if let Some(nonce) = value.nonce {
            execution.nonce(nonce)
        } else {
            execution
        };

        let execution = if let Some(max_fee) = value.max_fee {
            execution.max_fee(max_fee)
        } else {
            execution
        };

        execution.fee_estimate_multiplier(value.fee_estimate_multiplier)
    }
}

impl<'f, A> From<&DeploymentV3<'f, A>> for ExecutionV3<'f, A> {
    fn from(value: &DeploymentV3<'f, A>) -> Self {
        let mut calldata = vec![
            value.factory.class_hash,
            value.salt,
            if value.unique { Felt::ONE } else { Felt::ZERO },
            value.constructor_calldata.len().into(),
        ];
        calldata.extend_from_slice(&value.constructor_calldata);

        let execution = Self::new(
            vec![Call {
                to: value.factory.udc_address,
                selector: SELECTOR_DEPLOYCONTRACT,
                calldata,
            }],
            &value.factory.account,
        );

        let execution = if let Some(nonce) = value.nonce {
            execution.nonce(nonce)
        } else {
            execution
        };

        let execution = if let Some(gas) = value.gas {
            execution.gas(gas)
        } else {
            execution
        };

        let execution = if let Some(gas_price) = value.gas_price {
            execution.gas_price(gas_price)
        } else {
            execution
        };

        let execution = execution.gas_estimate_multiplier(value.gas_estimate_multiplier);

        execution.gas_price_estimate_multiplier(value.gas_price_estimate_multiplier)
    }
}
