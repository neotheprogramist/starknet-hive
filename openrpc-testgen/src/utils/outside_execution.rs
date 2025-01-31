use cainome_cairo_serde::CairoSerde;
use cainome_cairo_serde_derive::CairoSerde;
use crypto_utils::hash::{poseidon_hash_many, PoseidonHasher};
use starknet::core::crypto::ecdsa_sign;
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag};

use super::v7::{
    accounts::call::Call, endpoints::errors::OpenRpcTestGenError, providers::provider::Provider,
};

pub const STARKNET_DOMAIN_TYPE_HASH: Felt =
    Felt::from_hex_unchecked("0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210");
pub const CALL_TYPE_HASH: Felt =
    Felt::from_hex_unchecked("0x3635c7f2a7ba93844c0d064e18e487f35ab90f7c39d00f186a781fc3f0c2ca9");
pub const OUTSIDE_EXECUTION_TYPE_HASH: Felt =
    Felt::from_hex_unchecked("0x312b56c05a7965066ddbda31c016d8d05afc305071c0ca3cdc2192c3c2f1f0f");

#[derive(Debug, CairoSerde)]
pub struct OutsideExecution {
    pub caller: Felt,
    pub nonce: Felt,
    pub execute_after: u64,
    pub execute_before: u64,
    pub calls: Vec<Call>,
}

#[derive(Debug, CairoSerde)]
pub struct StarknetDomain {
    pub name: Felt,
    pub version: Felt,
    pub chain_id: Felt,
    pub revision: Felt,
}

pub fn get_starknet_domain_hash(chain_id: Felt) -> Felt {
    let domain = StarknetDomain {
        name: Felt::from_bytes_be_slice(b"Account.execute_from_outside"),
        version: Felt::TWO,
        chain_id,
        revision: Felt::ONE,
    };

    let domain_vec = vec![
        STARKNET_DOMAIN_TYPE_HASH,
        domain.name,
        domain.version,
        domain.chain_id,
        domain.revision,
    ];
    poseidon_hash_many(&domain_vec)
}

pub fn get_outside_execution_hash(outside_execution: &OutsideExecution) -> Felt {
    let calls_vec = outside_execution.calls.clone();
    let mut hashed_calls = Vec::<Felt>::new();

    for call in calls_vec {
        hashed_calls.push(get_call_hash(call));
    }

    let mut hasher_outside_execution = PoseidonHasher::new();
    hasher_outside_execution.update(OUTSIDE_EXECUTION_TYPE_HASH);
    hasher_outside_execution.update(outside_execution.caller);
    hasher_outside_execution.update(outside_execution.nonce);
    hasher_outside_execution.update(Felt::from(outside_execution.execute_after));
    hasher_outside_execution.update(Felt::from(outside_execution.execute_before));
    hasher_outside_execution.update(poseidon_hash_many(&hashed_calls));

    hasher_outside_execution.finalize()
}

pub fn get_call_hash(call: Call) -> Felt {
    let mut hasher_call = PoseidonHasher::new();
    hasher_call.update(CALL_TYPE_HASH);
    hasher_call.update(call.to);
    hasher_call.update(call.selector);
    hasher_call.update(poseidon_hash_many(&call.calldata));
    hasher_call.finalize()
}

pub async fn prepare_outside_execution(
    outside_execution: &OutsideExecution,
    signer_address: Felt,
    signer_private_key: Felt,
    chain_id: Felt,
) -> Result<Vec<Felt>, OpenRpcTestGenError> {
    let mut final_hasher = PoseidonHasher::new();
    final_hasher.update(Felt::from_bytes_be_slice(b"StarkNet Message"));
    final_hasher.update(get_starknet_domain_hash(chain_id));
    final_hasher.update(signer_address);
    final_hasher.update(get_outside_execution_hash(outside_execution));

    let hash = final_hasher.finalize();

    let starknet::core::crypto::ExtendedSignature { r, s, v: _ } =
        ecdsa_sign(&signer_private_key, &hash)?;

    let outside_execution_cairo_serialized = OutsideExecution::cairo_serialize(outside_execution);

    let mut calldata_to_executable_account_call = outside_execution_cairo_serialized.clone();
    calldata_to_executable_account_call.push(Felt::from_dec_str("2")?);
    calldata_to_executable_account_call.push(r);
    calldata_to_executable_account_call.push(s);

    Ok(calldata_to_executable_account_call)
}

pub async fn get_current_timestamp<P: Provider>(provider: P) -> Result<u64, OpenRpcTestGenError> {
    let block_with_tx_hashes = provider
        .get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest))
        .await?;

    let timestamp = match block_with_tx_hashes {
        starknet_types_rpc::MaybePendingBlockWithTxHashes::Block(block) => {
            block.block_header.timestamp
        }
        starknet_types_rpc::MaybePendingBlockWithTxHashes::Pending(block) => {
            block.pending_block_header.timestamp
        }
    };

    Ok(timestamp)
}
