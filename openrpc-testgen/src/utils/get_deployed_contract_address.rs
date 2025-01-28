use starknet_types_core::felt::Felt;
use starknet_types_rpc::TxnReceipt;

use super::v7::{
    endpoints::errors::{CallError, OpenRpcTestGenError},
    providers::provider::Provider,
};

pub async fn get_contract_address<P: Provider>(
    provider: P,
    deploy_transaction_hash: Felt,
) -> Result<Felt, OpenRpcTestGenError> {
    let deployment_receipt = provider
        .get_transaction_receipt(deploy_transaction_hash)
        .await?;

    let deployed_contract_address = match &deployment_receipt {
        TxnReceipt::Deploy(receipt) => receipt.contract_address,
        TxnReceipt::Invoke(receipt) => {
            if let Some(contract_address) = receipt
                .common_receipt_properties
                .events
                .first()
                .and_then(|event| event.data.first())
            {
                *contract_address
            } else {
                return Err(OpenRpcTestGenError::CallError(
                    CallError::UnexpectedReceiptType,
                ));
            }
        }
        _ => {
            return Err(OpenRpcTestGenError::CallError(
                CallError::UnexpectedReceiptType,
            ));
        }
    };
    Ok(deployed_contract_address)
}
