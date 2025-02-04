use std::future::Future;
use utils::v7::{
    accounts::single_owner::SingleOwnerAccount,
    endpoints::errors::OpenRpcTestGenError,
    providers::jsonrpc::{HttpTransport, JsonRpcClient},
    signers::local_wallet::LocalWallet,
};

pub mod macros;
#[cfg(feature = "katana")]
pub mod suite_katana;
#[cfg(feature = "katana_no_account_validation")]
pub mod suite_katana_no_account_validation;
#[cfg(feature = "katana_no_fee")]
pub mod suite_katana_no_fee;
#[cfg(feature = "katana_no_mining")]
pub mod suite_katana_no_mining;
#[cfg(feature = "openrpc")]
pub mod suite_openrpc;

pub mod utils;

pub trait RunnableTrait: Sized {
    type Input;

    fn run(input: &Self::Input) -> impl Future<Output = Result<Self, OpenRpcTestGenError>>;
}
pub trait SetupableTrait: Sized {
    type Input;

    fn setup(input: &Self::Input) -> impl Future<Output = Result<Self, OpenRpcTestGenError>>;
}

pub trait RandomizableAccountsTrait {
    #[allow(clippy::result_large_err)]
    fn random_accounts(
        &self,
    ) -> Result<SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>, OpenRpcTestGenError>;
}
