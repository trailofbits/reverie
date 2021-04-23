use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::crypto::{commit, Hash, Prg, KEY_SIZE};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MerkleSetProof {
    pub rand: [u8; KEY_SIZE], // commitment randomness
}

/// A cryptographic accumulator which additionally hides the unopened elements
///
/// A MerkleSet is a randomized MerkleTree which ameliorates the Merkle tree,
/// by committing to every leaf and permuting the leafs randomly.
///
/// This provides hiding of the unopened leafs.
#[derive(Debug, Clone)]
pub struct MerkleSet {
    rand: [u8; KEY_SIZE],
}

impl MerkleSetProof {
    pub fn verify(&self, leaf: &Hash) -> Hash {
        commit(&self.rand, leaf.as_bytes())
    }
}
