use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::crypto::{commit, Hash, Prg, KEY_SIZE};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MerkleSetProof {
    rand: [u8; KEY_SIZE], // commitment randomness
}

impl MerkleSetProof {
    pub fn new(rand: [u8; KEY_SIZE]) -> MerkleSetProof {
        MerkleSetProof{
            rand
        }
    }

    pub fn verify(&self, leaf: &Hash) -> Hash {
        commit(&self.rand, leaf.as_bytes())
    }
}
