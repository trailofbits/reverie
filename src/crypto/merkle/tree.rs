use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::crypto::{Hash, Hasher};

#[derive(Debug, Clone)]
pub enum MerkleTree {
    Leaf(Hash),
    Internal(usize, Hash, Arc<MerkleTree>, Arc<MerkleTree>),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MerkleProof {
    path: u32, // only supports up to 2^32 leafs
    leafs: Vec<Hash>,
}

fn merkle_internal(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(&[0u8]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize()
}

impl MerkleTree {
    pub fn new(elems: &[Hash]) -> MerkleTree {
        assert!(!elems.is_empty());
        assert_eq!(elems.len(), 1);
        MerkleTree::Leaf(elems[0].clone())
    }

    fn size(&self) -> usize {
        match self {
            MerkleTree::Leaf(_) => 1,
            MerkleTree::Internal(size, _, _, _) => *size,
        }
    }

    pub fn root(&self) -> &Hash {
        match self {
            MerkleTree::Leaf(hash) => hash,
            MerkleTree::Internal(_, root, _, _) => root,
        }
    }

    pub fn prove(&self, index: usize) -> MerkleProof {
        MerkleProof {
            path: 0,
            leafs: Vec::with_capacity(32),
        }
    }
}
