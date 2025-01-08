use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, FunctionCall};

use super::v7::{
    endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
    providers::provider::Provider,
};

/// Gets the balance of a given account address in the given contract address
/// and given block number.
///
/// # Arguments
///
/// * `provider`: The provider to use for the rpc call.
/// * `account_address`: The account address to get the balance for.
/// * `contract_address`: The contract address to get the balance from.
/// * `block_id`: The block number to get the balance for.
///
/// # Returns
///
/// A vector of `Felt`s, representing the balance of the given account address
/// in the given contract address at the given block number.
pub async fn get_balance<P: Provider>(
    provider: P,
    account_address: Felt,
    contract_address: Felt,
    block_id: BlockId<Felt>,
) -> Result<Vec<Felt>, OpenRpcTestGenError> {
    let balance = provider
        .call(
            FunctionCall {
                calldata: vec![account_address],
                contract_address,
                entry_point_selector: get_selector_from_name("balance_of")?,
            },
            block_id,
        )
        .await?;
    Ok(balance)
}
