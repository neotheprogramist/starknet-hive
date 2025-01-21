use super::constants::{DATA_AVAILABILITY_MODE_BITS, PREFIX_CONTRACT_CLASS_V0_1_0, PREFIX_DECLARE};
use crate::txn_validation::errors::Error;
use crypto_utils::curve::signer::compute_hash_on_elements;
use sha3::{Digest, Keccak256};
use starknet_types_core::felt::{Felt, NonZeroFelt};
use starknet_types_core::hash::{Poseidon, StarkHash};
use starknet_types_rpc::v0_7_1::starknet_api_openrpc::*;
use starknet_types_rpc::v0_7_1::SierraEntryPoint;

// 2 ** 251 - 256
const ADDR_BOUND: NonZeroFelt = NonZeroFelt::from_raw([
    576459263475590224,
    18446744073709255680,
    160989183,
    18446743986131443745,
]);

pub fn calculate_declare_v2_hash(
    txn: &BroadcastedDeclareTxnV2<Felt>,
    chain_id: &Felt,
) -> Result<Felt, Error> {
    Ok(compute_hash_on_elements(&[
        PREFIX_DECLARE,
        Felt::TWO, // version
        txn.sender_address,
        Felt::ZERO, // entry_point_selector
        compute_hash_on_elements(&[class_hash(txn.contract_class.clone())]),
        txn.max_fee,
        *chain_id,
        txn.nonce,
        txn.compiled_class_hash,
    ]))
}

pub fn calculate_declare_v3_hash(
    txn: &BroadcastedDeclareTxnV3<Felt>,
    chain_id: &Felt,
) -> Result<Felt, Error> {
    let class_hash = class_hash(txn.contract_class.clone());

    let account_deployment_data_hash = Poseidon::hash_array(&txn.account_deployment_data);

    let fields_to_hash = [
        common_fields_for_hash(PREFIX_DECLARE, *chain_id, txn)?.as_slice(),
        &[account_deployment_data_hash],
        &[class_hash],
        &[txn.compiled_class_hash],
    ]
    .concat();

    // Compute the final transaction hash
    Ok(Poseidon::hash_array(&fields_to_hash))
}

pub fn class_hash(contract_class: ContractClass<Felt>) -> Felt {
    let data = vec![
        PREFIX_CONTRACT_CLASS_V0_1_0,
        hash_entrypoints(&contract_class.entry_points_by_type.external),
        hash_entrypoints(&contract_class.entry_points_by_type.l1_handler),
        hash_entrypoints(&contract_class.entry_points_by_type.constructor),
        starknet_keccak(contract_class.abi.clone().expect("abi expected").as_bytes()),
        Poseidon::hash_array(&contract_class.sierra_program),
    ];

    normalize_address(Poseidon::hash_array(&data))
}

fn normalize_address(address: Felt) -> Felt {
    address.mod_floor(&ADDR_BOUND)
}

fn hash_entrypoints(entrypoints: &[SierraEntryPoint<Felt>]) -> Felt {
    let mut data = Vec::new();
    for entry in entrypoints.iter() {
        data.push(entry.selector);
        data.push(entry.function_idx.into());
    }

    Poseidon::hash_array(&data)
}
fn starknet_keccak(data: &[u8]) -> Felt {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut hash = hasher.finalize();

    // Remove the first 6 bits
    hash[0] &= 0b00000011;

    // Because we know hash is always 32 bytes
    Felt::from_bytes_be(unsafe { &*(hash[..].as_ptr() as *const [u8; 32]) })
}

/// Returns the array of Felts that reflects (tip, resource_bounds_for_fee) from SNIP-8
fn get_resource_bounds_array(txn: &BroadcastedDeclareTxnV3<Felt>) -> Result<Vec<Felt>, Error> {
    Ok(vec![
        txn.tip,
        field_element_from_resource_bounds(Resource::L1Gas, &txn.resource_bounds.l1_gas)?,
        field_element_from_resource_bounds(Resource::L2Gas, &txn.resource_bounds.l2_gas)?,
    ])
}

fn field_element_from_resource_bounds(
    resource: Resource,
    resource_bounds: &ResourceBounds,
) -> Result<Felt, Error> {
    let resource_name_as_json_string = serde_json::to_value(resource)?;

    // Ensure it's a string and get bytes
    let resource_name_bytes = resource_name_as_json_string
        .as_str()
        .ok_or(Error::ResourceNameError)?
        .as_bytes();

    let max_amount_hex_str = resource_bounds.max_amount.as_str().trim_start_matches("0x");
    let max_amount_u64 = u64::from_str_radix(max_amount_hex_str, 16)?;

    let max_price_per_unit_hex_str = resource_bounds
        .max_price_per_unit
        .as_str()
        .trim_start_matches("0x");
    let max_price_per_unit_u64 = u128::from_str_radix(max_price_per_unit_hex_str, 16)?;

    // (resource||max_amount||max_price_per_unit) from SNIP-8 https://github.com/starknet-io/SNIPs/blob/main/SNIPS/snip-8.md#protocol-changes
    let bytes: Vec<u8> = [
        resource_name_bytes,
        max_amount_u64.to_be_bytes().as_slice(),
        max_price_per_unit_u64.to_be_bytes().as_slice(),
    ]
    .into_iter()
    .flatten()
    .copied()
    .collect();

    Ok(Felt::from_bytes_be_slice(&bytes))
}

fn common_fields_for_hash(
    tx_prefix: Felt,
    chain_id: Felt,
    txn: &BroadcastedDeclareTxnV3<Felt>,
) -> Result<Vec<Felt>, Error> {
    let array: Vec<Felt> = vec![
        tx_prefix,                                                        // TX_PREFIX
        Felt::THREE,                                                      // version
        txn.sender_address,                                               // address
        Poseidon::hash_array(get_resource_bounds_array(txn)?.as_slice()), /* h(tip, resource_bounds_for_fee) */
        Poseidon::hash_array(&txn.paymaster_data),                        // h(paymaster_data)
        chain_id,                                                         // chain_id
        txn.nonce,                                                        // nonce
        get_data_availability_modes_field_element(txn), /* nonce_data_availability ||
                                                         * fee_data_availability_mode */
    ];

    Ok(array)
}

fn get_data_availability_mode_value_as_u64(data_availability_mode: DaMode) -> u64 {
    match data_availability_mode {
        DaMode::L1 => 0,
        DaMode::L2 => 1,
    }
}

/// Returns Felt that encodes the data availability modes of the transaction
fn get_data_availability_modes_field_element(txn: &BroadcastedDeclareTxnV3<Felt>) -> Felt {
    let da_mode = get_data_availability_mode_value_as_u64(txn.nonce_data_availability_mode.clone())
        << DATA_AVAILABILITY_MODE_BITS;
    let da_mode =
        da_mode + get_data_availability_mode_value_as_u64(txn.fee_data_availability_mode.clone());
    Felt::from(da_mode)
}
