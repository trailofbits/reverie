use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::crypto::{commit, Hash, Prg, KEY_SIZE};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MerkleSetProof {
    rand: [u8; KEY_SIZE], // commitment randomness
}

impl MerkleSetProof {
    pub fn new(seed: [u8; KEY_SIZE]) -> MerkleSetProof {
        let mut rng = Prg::new(seed);
        MerkleSetProof { rand: rng.gen() }
    }

    pub fn verify(&self) -> Hash {
        commit(&self.rand)
    }
}
