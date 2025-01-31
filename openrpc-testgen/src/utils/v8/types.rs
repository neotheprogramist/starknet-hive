use serde::{Deserialize, Serialize};
use starknet_types_core::{
    felt::Felt,
    hash::{Pedersen, Poseidon, StarkHash},
};
use starknet_types_rpc::BlockId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetStorageProofParams<F> {
    pub block_id: BlockId<F>,
    pub class_hashes: Option<Vec<F>>,
    pub contract_addresses: Option<Vec<F>>,
    pub contracts_storage_keys: Option<Vec<ContractStorageKeysItem>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractStorageKeysItem {
    pub contract_address: Felt,
    pub storage_keys: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetStorageProofResult {
    pub classes_proof: Vec<NodeHashToNodeMappingItem>,
    pub contracts_proof: ContractsProof,
    pub contracts_storage_proofs: Vec<Vec<NodeHashToNodeMappingItem>>,
    pub global_roots: GlobalRoots,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeHashToNodeMappingItem {
    pub node_hash: Felt,
    pub node: MerkleNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MerkleNode {
    Binary {
        left: Felt,
        right: Felt,
    },
    Edge {
        child: Felt,
        path: Felt,
        length: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractsProof {
    pub nodes: Vec<NodeHashToNodeMappingItem>,
    pub contract_leaves_data: Vec<ContractLeavesDataItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractLeavesDataItem {
    pub nonce: Felt,
    pub class_hash: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalRoots {
    pub contracts_tree_root: Felt,
    pub classes_tree_root: Felt,
    pub block_hash: Felt,
}

#[derive(Debug)]
pub struct MerkleTreeMadara {
    nodes: Vec<NodeHashToNodeMappingItem>,
    root: Felt,
}

impl MerkleTreeMadara {
    pub fn from_proof(proof: Vec<NodeHashToNodeMappingItem>, root_hash: Felt) -> Self {
        MerkleTreeMadara {
            nodes: proof,
            root: root_hash,
        }
    }

    pub fn find_edge_node(&self) -> Option<&NodeHashToNodeMappingItem> {
        for node in &self.nodes {
            if let MerkleNode::Edge { .. } = node.node {
                return Some(node);
            }
        }
        None
    }

    pub fn compute_edge_hash(&self) {
        let edge_node = self.find_edge_node();
        if edge_node.is_none() {
            println!("❌ EdgeNode not found!");
            return;
        }
        let edge = edge_node.unwrap();
        println!("--- EdgeNode ---");
        println!("{:#?}", edge);

        let child = match &edge.node {
            MerkleNode::Edge { child, .. } => *child,
            _ => panic!("Expected an Edge node"),
        };

        let path = match &edge.node {
            MerkleNode::Edge { path, .. } => *path,
            _ => panic!("Expected an Edge node"),
        };

        let length = match &edge.node {
            MerkleNode::Edge { length, .. } => *length,
            _ => panic!("Expected an Edge node"),
        };

        let length_felt = Felt::from(length);

        println!("--- EdgeNode Debug ---");
        println!("Child: {:#?}", child);
        println!("Path: {:#?}", path);
        println!("Length: {}", length);

        let computed_poseidon = Poseidon::hash(&child, &path) + length_felt;
        let computed_pedersen = Pedersen::hash(&child, &path) + length_felt;

        println!("Poseidon(child, path) + length: {:#?}", computed_poseidon);
        println!("Pedersen(child, path) + length: {:#?}", computed_pedersen);

        println!("Expected node_hash: {:#?}", edge.node_hash);

        if computed_poseidon == edge.node_hash {
            println!("✅ Poseidon hash matches the expected node_hash!");
        } else {
            println!("❌ Poseidon hash does NOT match!");
        }

        if computed_pedersen == edge.node_hash {
            println!("✅ Pedersen hash matches the expected node_hash!");
        } else {
            println!("❌ Pedersen hash does NOT match!");
        }

        println!("----------------------");
    }
}
