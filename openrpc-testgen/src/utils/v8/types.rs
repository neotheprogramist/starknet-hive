use serde::{Deserialize, Serialize};
use starknet::macros::short_string;
use starknet_types_core::{
    felt::Felt,
    hash::{Pedersen, Poseidon, StarkHash},
};
use starknet_types_rpc::BlockId;
use std::collections::HashMap;
use thiserror::Error;

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

#[derive(Debug)]
pub struct MerkleTree {
    nodes: HashMap<Felt, TreeNode>,
    root: Felt,
}

#[derive(Debug, Clone)]
pub struct TreeNode {
    pub node: MerkleNode,
    pub node_hash: Felt,
    pub parent_hash: Option<Felt>,
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

type HashFn = fn(&Felt, &Felt) -> Felt;

const CONTRACT_CLASS_LEAF_V0: Felt = short_string!("CONTRACT_CLASS_LEAF_V0");

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("Expected a Binary node, but found an Edge node.")]
    ExpectedBinaryNode,
    #[error("Expected an Edge node, but found a Binary node.")]
    ExpectedEdgeNode,
    #[error("No matching edge node found for expected child {0:?}.")]
    NoMatchingEdgeNode(Felt),

    #[error("No parent found for node with hash {0:?}.")]
    NoParentFound(Felt),

    #[error("Computed child hash {computed:?} does not match any of the parent's children. Parent node {node_hash:?} has left {left:?} and right {right:?}.")]
    ChildMismatch {
        computed: Felt,
        left: Felt,
        right: Felt,
        node_hash: Felt,
    },

    #[error("Computed edge hash {computed:?} does not match parent's child field. Parent node {node_hash:?} expected child {child:?}.")]
    EdgeChildMismatch {
        computed: Felt,
        child: Felt,
        node_hash: Felt,
    },

    #[error("Missing contract leaves data for contract {contract_address:?}.")]
    MissingContractLeavesData { contract_address: Felt },

    #[error("Missing contract leaves data for contract {contract_address:?} at slot {slot:?}.")]
    MissingContractStorageProofData { contract_address: Felt, slot: Felt },
}

impl MerkleTree {
    /// Constructs a `MerkleTree` from a given proof and root hash.
    ///
    /// This function processes a vector of `NodeHashToNodeMappingItem`, which represents
    /// the nodes in a Merkle tree, to reconstruct the tree structure. It creates a map
    /// of nodes and establishes parent-child relationships based on the proof data.
    ///
    /// # Arguments
    ///
    /// * `proof` - A vector of `NodeHashToNodeMappingItem` that contains the node hash
    ///   and corresponding `MerkleNode`. This proof provides the structure needed to
    ///   build the tree.
    /// * `root_hash` - The hash of the root node of the Merkle tree.
    ///
    /// # Returns
    ///
    /// A `MerkleTree` instance with nodes and their parent relationships
    /// reconstructed from the provided proof.
    pub fn from_proof(proof: Vec<NodeHashToNodeMappingItem>, root_hash: Option<Felt>) -> Self {
        let mut nodes = HashMap::new();
        let mut child_to_parent = HashMap::new();

        for node in &proof {
            match &node.node {
                MerkleNode::Binary { left, right } => {
                    child_to_parent.insert(*left, node.node_hash);
                    child_to_parent.insert(*right, node.node_hash);
                }
                MerkleNode::Edge { child, .. } => {
                    child_to_parent.insert(*child, node.node_hash);
                }
            }
        }

        for node in proof {
            let parent_hash = child_to_parent.get(&node.node_hash).copied();
            nodes.insert(
                node.node_hash,
                TreeNode {
                    node: node.node,
                    node_hash: node.node_hash,
                    parent_hash,
                },
            );
        }

        // In certain scenarios (contract storage proof), the root hash needs to be found before the computation
        let root_hash = root_hash.unwrap_or_else(|| {
            nodes
                .iter()
                .find(|(_, node)| node.parent_hash.is_none())
                .map(|(key, _)| *key)
                .expect("Failed to determine root hash from proof")
        });

        MerkleTree {
            nodes,
            root: root_hash,
        }
    }

    /// Finds and returns a reference to the `TreeNode` containing an edge node
    /// whose child field matches the given `expected_child`.
    ///
    /// This function iterates over all nodes in the Merkle tree and checks if they
    /// are edge nodes with a child field equal to `expected_child`.
    ///
    /// # Arguments
    ///
    /// * `expected_child` - A reference to a `Felt` representing the expected child
    ///   hash of the edge node.
    ///
    /// # Returns
    ///
    /// An `Option` containing a reference to the matching `TreeNode` if found,
    /// or `None` if no such node exists.
    pub fn find_matching_edge_node(&self, expected_child: &Felt) -> Option<&TreeNode> {
        self.nodes.values().find(|node| {
            if let MerkleNode::Edge { child, .. } = &node.node {
                child == expected_child
            } else {
                false
            }
        })
    }
    #[allow(clippy::result_large_err)]
    /// Computes the hash of a given `TreeNode` using the specified hash function.
    ///
    /// # Arguments
    ///
    /// * `node` - A reference to a `TreeNode` for which the hash needs to be computed.
    /// * `hash_fn` - A function that takes two `Felt` references and returns their combined hash as a `Felt`.
    ///
    /// # Returns
    ///
    /// A `Result` containing the computed hash as `Felt` if successful, or a `ProofError` if an error occurs.
    ///
    /// The hashing process differs based on the type of `MerkleNode`:
    /// - For `Binary` nodes, the hash is computed from the `left` and `right` fields.
    /// - For `Edge` nodes, the hash is computed from the `child` and `path` fields, with the `length` added to the result.
    pub fn compute_node_hash(&self, node: &TreeNode, hash_fn: HashFn) -> Result<Felt, ProofError> {
        match &node.node {
            MerkleNode::Binary { left, right } => Ok(hash_fn(left, right)),
            MerkleNode::Edge {
                child,
                path,
                length,
            } => Ok(hash_fn(child, path) + Felt::from(*length)),
        }
    }

    #[allow(clippy::result_large_err)]
    /// Verifies the storatge proof in the Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `expected_child` - The expected child child value of edge node
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the proof is valid, or `Err(ProofError)` if the proof is invalid.
    ///
    /// The verification process works as follows:
    ///
    /// 1. Find the edge node in the Merkle tree with the given expected child hash.
    /// 2. Compute the hash of the edge node.
    /// 3. Iterate over the parents of the edge node until the root of the Merkle tree
    ///    is reached. For each parent, check that the child field matches the current
    ///    hash, and if so, compute the hash of the parent.
    /// 4. If the final computed root matches the root of the Merkle tree, return
    ///    `true`, otherwise return an error.
    pub fn verify_proof(&self, expected_child: &Felt, hash_fn: HashFn) -> Result<bool, ProofError> {
        let edge_node = self
            .find_matching_edge_node(expected_child)
            .ok_or(ProofError::NoMatchingEdgeNode(*expected_child))?;
        let mut current_node = edge_node;
        let mut current_hash = self.compute_node_hash(current_node, hash_fn)?;

        while let Some(parent_hash) = current_node.parent_hash {
            let parent = self
                .nodes
                .get(&parent_hash)
                .ok_or(ProofError::NoParentFound(parent_hash))?;

            // Check if the computed hash is equal to any of the parent's children, or if it matches the parent's child field
            match &parent.node {
                MerkleNode::Binary { left, right } => {
                    if *left != current_hash && *right != current_hash {
                        return Err(ProofError::ChildMismatch {
                            computed: current_hash,
                            left: *left,
                            right: *right,
                            node_hash: parent.node_hash,
                        });
                    }
                }
                MerkleNode::Edge { child, .. } => {
                    if *child != current_hash {
                        return Err(ProofError::EdgeChildMismatch {
                            computed: current_hash,
                            child: *child,
                            node_hash: parent.node_hash,
                        });
                    }
                }
            }

            current_hash = self.compute_node_hash(parent, hash_fn)?;
            current_node = parent;
        }

        Ok(current_hash == self.root)
    }

    pub fn compute_expected_child_for_class_proof(&self, compiled_class_hash: &Felt) -> Felt {
        // https://docs.starknet.io/architecture-and-concepts/network-architecture/starknet-state/
        Poseidon::hash(&CONTRACT_CLASS_LEAF_V0, compiled_class_hash)
    }

    pub fn compute_expected_child_for_contract_proof(
        &self,
        class_hash: &Felt,
        storage_root: &Felt,
        nonce: &Felt,
    ) -> Felt {
        // https://docs.starknet.io/architecture-and-concepts/network-architecture/starknet-state/
        let hash1 = Pedersen::hash(class_hash, storage_root);
        let hash2 = Pedersen::hash(&hash1, nonce);
        Pedersen::hash(&hash2, &Felt::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_proof() -> Result<(), ProofError> {
        let proof = vec![
            NodeHashToNodeMappingItem {
                node_hash: Felt::from_hex(
                    "0x2085dc49422286bbf425f254038cc9cd9a1d4759e7dcc1bb8c9cf1226d0930a",
                )
                .unwrap(),
                node: MerkleNode::Binary {
                    left: Felt::from_hex(
                        "0x405224321493720f122542353165c45f64b2c24e322a73e6279c01cd2d5d827",
                    )
                    .unwrap(),
                    right: Felt::from_hex(
                        "0x66994ccdf80a945964523771da2dafc828439dc4b74544c65112c4bf0cd6061",
                    )
                    .unwrap(),
                },
            },
            NodeHashToNodeMappingItem {
                node_hash: Felt::from_hex(
                    "0x66994ccdf80a945964523771da2dafc828439dc4b74544c65112c4bf0cd6061",
                )
                .unwrap(),
                node: MerkleNode::Edge {
                    child: Felt::from_hex(
                        "0x5fb485c397598b6a672ff3dd38c121d20bbec276b881b0a6e9aba874855f376",
                    )
                    .unwrap(),
                    path: Felt::from_hex("0x1").unwrap(),
                    length: 1,
                },
            },
            NodeHashToNodeMappingItem {
                node_hash: Felt::from_hex(
                    "0x5fb485c397598b6a672ff3dd38c121d20bbec276b881b0a6e9aba874855f376",
                )
                .unwrap(),
                node: MerkleNode::Binary {
                    left: Felt::from_hex(
                        "0x39cc46c8a1ffa39802074dcd2aabd4814b8eb8f65a3f0ca6a6138f2bdd691f8",
                    )
                    .unwrap(),
                    right: Felt::from_hex(
                        "0x311d6cf5f2d545f0ac4dd421e571aa8c11beb3d5b73417b9e54ec828304e92c",
                    )
                    .unwrap(),
                },
            },
            NodeHashToNodeMappingItem {
                node_hash: Felt::from_hex(
                    "0x39cc46c8a1ffa39802074dcd2aabd4814b8eb8f65a3f0ca6a6138f2bdd691f8",
                )
                .unwrap(),
                node: MerkleNode::Edge {
                    child: Felt::from_hex(
                        "0x31f329f9df950bed8c8218bc3b24f0bbe8d7ff8707b060b31f8342bddd6747a",
                    )
                    .unwrap(),
                    path: Felt::from_hex(
                        "0x93b752a80b9ce2b0f8b0b6dc3125ef31218d87c8c1c9959389ff53f73897a1",
                    )
                    .unwrap(),
                    length: 248,
                },
            },
        ];
        let root_hash =
            Felt::from_hex("0x2085dc49422286bbf425f254038cc9cd9a1d4759e7dcc1bb8c9cf1226d0930a")
                .unwrap();
        let tree = MerkleTree::from_proof(proof, Some(root_hash));
        let compiled_class_hash =
            Felt::from_hex("0x462f79bccfd948fc9f47936f18729ed2850113f5f3f487b1a70ee208c7d79e0")
                .unwrap();
        let expected_child = tree.compute_expected_child_for_class_proof(&compiled_class_hash);
        let valid = tree.verify_proof(&expected_child, Poseidon::hash)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_invalid_proof() -> Result<(), ProofError> {
        let proof = vec![
            NodeHashToNodeMappingItem {
                node_hash: Felt::from_hex(
                    "0x2085dc49422286bbf425f254038cc9cd9a1d4759e7dcc1bb8c9cf1226d0930a",
                )
                .unwrap(),
                node: MerkleNode::Binary {
                    left: Felt::from_hex(
                        "0x405224321493720f122542353165c45f64b2c24e322a73e6279c01cd2d5d827",
                    )
                    .unwrap(),
                    right: Felt::from_hex(
                        "0x66994ccdf80a945964523771da2dafc828439dc4b74544c65112c4bf0cd6061",
                    )
                    .unwrap(),
                },
            },
            NodeHashToNodeMappingItem {
                node_hash: Felt::from_hex(
                    "0x66994ccdf80a945964523771da2dafc828439dc4b74544c65112c4bf0cd6061",
                )
                .unwrap(),
                node: MerkleNode::Edge {
                    child: Felt::from_hex(
                        "0x5fb485c397598b6a672ff3dd38c121d20bbec276b881b0a6e9aba874855f376",
                    )
                    .unwrap(),
                    path: Felt::from_hex("0x1").unwrap(),
                    length: 1,
                },
            },
            NodeHashToNodeMappingItem {
                node_hash: Felt::from_hex(
                    "0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
                )
                .unwrap(),
                node: MerkleNode::Binary {
                    left: Felt::from_hex(
                        "0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
                    )
                    .unwrap(),
                    right: Felt::from_hex(
                        "0xFEEDBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
                    )
                    .unwrap(),
                },
            },
            NodeHashToNodeMappingItem {
                node_hash: Felt::from_hex(
                    "0x39cc46c8a1ffa39802074dcd2aabd4814b8eb8f65a3f0ca6a6138f2bdd691f8",
                )
                .unwrap(),
                node: MerkleNode::Edge {
                    child: Felt::from_hex(
                        "0x31f329f9df950bed8c8218bc3b24f0bbe8d7ff8707b060b31f8342bddd6747a",
                    )
                    .unwrap(),
                    path: Felt::from_hex(
                        "0x93b752a80b9ce2b0f8b0b6dc3125ef31218d87c8c1c9959389ff53f73897a1",
                    )
                    .unwrap(),
                    length: 248,
                },
            },
        ];
        let root_hash =
            Felt::from_hex("0x2085dc49422286bbf425f254038cc9cd9a1d4759e7dcc1bb8c9cf1226d0930a")
                .unwrap();
        let tree = MerkleTree::from_proof(proof, Some(root_hash));
        let compiled_class_hash =
            Felt::from_hex("0x462f79bccfd948fc9f47936f18729ed2850113f5f3f487b1a70ee208c7d79e0")
                .unwrap();
        let expected_child = tree.compute_expected_child_for_class_proof(&compiled_class_hash);
        let valid = tree.verify_proof(&expected_child, Poseidon::hash)?;
        assert!(!valid);
        Ok(())
    }
}
