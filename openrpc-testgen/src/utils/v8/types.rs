use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
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
pub struct MerkleTree {
    nodes: HashMap<Felt, MerkleNode>,
    root: Felt,
}

impl MerkleTree {
    /// Tworzy instancję MerkleTree z dowodu i korzenia
    pub fn from_proof(proof: Vec<NodeHashToNodeMappingItem>, root_hash: Felt) -> Self {
        let mut nodes = HashMap::new();
        for node in &proof {
            nodes.insert(node.node_hash.clone(), node.node.clone());
        }
        MerkleTree {
            nodes,
            root: root_hash,
        }
    }

    pub fn compute_root<F>(&self, hash_fn: F) -> Felt
    where
        F: Fn(&Felt, &Felt) -> Felt,
    {
        let edge_node_hashes: Vec<Felt> = self
            .nodes
            .iter()
            .filter_map(|(hash, node)| {
                if let MerkleNode::Edge { .. } = node {
                    Some(hash.clone())
                } else {
                    None
                }
            })
            .collect();

        if edge_node_hashes.is_empty() {
            panic!("No Edge node found in the proof.");
        }

        // Zakładamy, że jest tylko jeden węzeł typu `Edge`
        let start_hash = edge_node_hashes[0].clone();
        let mut current_hash = start_hash.clone();
        let mut steps = 0;
        let max_steps = 1000;

        println!(
            "Starting compute_root with Edge node_hash: {:#?}",
            current_hash
        );

        loop {
            steps += 1;
            if steps > max_steps {
                println!(
                    "Exceeded maximum steps ({}) without reaching root.",
                    max_steps
                );
                break;
            }

            // Find node with current_hash as left lub right
            let parent_node = self.nodes.iter().find_map(|(hash, node)| match node {
                MerkleNode::Binary { left, right } => {
                    if left == &current_hash || right == &current_hash {
                        Some((hash.clone(), node.clone()))
                    } else {
                        None
                    }
                }
                MerkleNode::Edge { child, path, .. } => {
                    if child == &current_hash {
                        Some((hash.clone(), node.clone()))
                    } else {
                        None
                    }
                }
            });

            match parent_node {
                Some((parent_hash, node)) => {
                    match node {
                        MerkleNode::Binary { left, right } => {
                            println!(
                                "Binary node found: parent_hash = {:#?}, left = {:#?}, right = {:#?}",
                                parent_hash, left, right
                            );
                            // Oblicz parent_hash
                            let computed_parent_hash = hash_fn(&left, &right);
                            println!(
                                "Computed parent_hash: {:#?} (expected: {:#?})",
                                computed_parent_hash, parent_hash
                            );
                            current_hash = computed_parent_hash;
                            // Sprawdź, czy osiągnęliśmy korzeń
                            if current_hash == self.root {
                                println!("Reached root hash.");
                                break;
                            }
                        }
                        MerkleNode::Edge { child, path, .. } => {
                            println!(
                                "Edge node found: parent_hash = {:#?}, child = {:#?}, path = {:#?}",
                                parent_hash, child, path
                            );
                            // Oblicz parent_hash
                            let computed_parent_hash = hash_fn(&path, &child);
                            println!(
                                "Computed parent_hash: {:#?} (expected: {:#?})",
                                computed_parent_hash, parent_hash
                            );
                            current_hash = computed_parent_hash;
                            // Sprawdź, czy osiągnęliśmy korzeń
                            if current_hash == self.root {
                                println!("Reached root hash.");
                                break;
                            }
                        }
                    }
                }
                None => {
                    println!("No parent node found for current_hash: {:#?}", current_hash);
                    break;
                }
            }
        }

        println!("Final computed root: {:#?}", current_hash);
        current_hash
    }
}

pub fn verify_merkle_proof(
    classes_proof: Vec<NodeHashToNodeMappingItem>,
    expected_root: Felt,
    hash_fn: impl Fn(&Felt, &Felt) -> Felt,
) -> bool {
    let tree = MerkleTree::from_proof(classes_proof, expected_root);
    let computed_root = tree.compute_root(hash_fn);
    println!(
        "Computed root: {:#?}, Expected root: {:#?}",
        computed_root, expected_root
    );
    computed_root == expected_root
}
