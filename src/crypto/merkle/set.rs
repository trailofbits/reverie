use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::crypto::{commit, Hash, Prg, KEY_SIZE};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProofCommitment {
    rand: [u8; KEY_SIZE], // commitment randomness
}

impl ProofCommitment {
    pub fn new(seed: [u8; KEY_SIZE]) -> ProofCommitment {
        let mut rng = Prg::new(seed);
        ProofCommitment { rand: rng.gen() }
    }

    pub fn verify(&self) -> Hash {
        commit(&self.rand)
    }
}
