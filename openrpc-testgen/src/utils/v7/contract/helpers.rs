use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};

use crate::utils::v7::accounts::deployment::helpers::get_contract_address;

/// Computes the target contract address for deployments through the Universal Deploy Contract.
pub fn get_udc_deployed_address(
    salt: Felt,
    class_hash: Felt,
    uniqueness: &UdcUniqueness,
    constructor_calldata: &[Felt],
) -> Felt {
    match uniqueness {
        UdcUniqueness::NotUnique => {
            get_contract_address(salt, class_hash, constructor_calldata, Felt::ZERO)
        }
        UdcUniqueness::Unique(settings) => {
            let unique_salt = Pedersen::hash(&settings.deployer_address, &salt);
            get_contract_address(
                unique_salt,
                class_hash,
                constructor_calldata,
                settings.udc_contract_address,
            )
        }
    }
}

/// The uniqueness settings for UDC deployments.
#[derive(Debug, Clone)]
pub enum UdcUniqueness {
    NotUnique,
    Unique(UdcUniqueSettings),
}

#[derive(Debug, Clone)]
pub struct UdcUniqueSettings {
    pub deployer_address: Felt,
    pub udc_contract_address: Felt,
}
