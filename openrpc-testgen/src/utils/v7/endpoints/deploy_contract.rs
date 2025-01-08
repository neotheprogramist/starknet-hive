use std::fmt::Debug;

use rand::{rngs::StdRng, RngCore, SeedableRng};
use starknet_types_core::felt::Felt;
use starknet_types_core::felt::FromStrError;
use starknet_types_rpc::v0_7_1::AddInvokeTransactionResult;

use thiserror::Error;

use crate::utils::v7::{
    accounts::single_owner::SingleOwnerAccount,
    contract::factory::ContractFactory,
    providers::provider::{Provider, ProviderError},
    signers::local_wallet::LocalWallet,
};

use super::declare_contract::RunnerError;

#[derive(Error, Debug)]
pub enum DeployError {
    #[error("Error creating an account")]
    CreateAccount(String),

    #[error(transparent)]
    Provider(#[from] ProviderError),

    #[error(transparent)]
    FromStr(#[from] FromStrError),

    #[error(transparent)]
    Runner(#[from] RunnerError),
}

pub async fn deploy_contract<P: Provider + Send + Sync + Debug>(
    account: &SingleOwnerAccount<P, LocalWallet>,
    class_hash: Felt,
) -> AddInvokeTransactionResult<Felt> {
    let factory = ContractFactory::new(class_hash, account);
    let mut salt_buffer = [0u8; 32];
    let mut rng = StdRng::from_entropy();
    rng.fill_bytes(&mut salt_buffer[1..]);

    factory
        .deploy_v3(vec![], Felt::from_bytes_be(&salt_buffer), true)
        .send()
        .await
        .unwrap()
}
