use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

pub use prover::StreamingProver;
pub use verifier::StreamingVerifier;

use crate::algebra::{Domain, RingElement};
use crate::crypto::{Hash, KEY_SIZE, MerkleSetProof, RingHasher, TreePRF};
use crate::Instruction;
use crate::fieldswitching::preprocessing;

pub mod prover;
pub mod verifier;

#[derive(Debug, Serialize, Deserialize)]
pub struct Chunk {
    corrections: Vec<u8>,
    broadcast: Vec<u8>,
    witness: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Run<D: Domain, D2: Domain> {
    open: TreePRF,         // randomness for opened players
    proof: MerkleSetProof, // merkle proof for masked branch
    branch: Vec<u8>,       // masked branch (packed)
    commitment: Hash,      // commitment for hidden preprocessing player
    _ph: PhantomData<D>,
    _ph2: PhantomData<D2>,
}

/// Online execution "proof header"
///
/// Holds the (constant sized) state required to initialize the streaming online verifier
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<D: Domain, D2: Domain> {
    runs: Vec<Run<D, D2>>,
    _ph: PhantomData<D>,
    _ph2: PhantomData<D2>,
}

impl<D: Domain + Serialize, D2: Domain + Serialize> Proof<D, D2> {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

impl<'de, D: Domain + Deserialize<'de>, D2: Domain + Deserialize<'de>> Proof<D, D2> {
    pub fn deserialize(encoded: &'de [u8]) -> Option<Self> {
        bincode::deserialize(encoded).ok()
    }
}

/// This struct ensures that the user can only get access to the output (private field)
/// by validating the online execution against a correctly validated and matching pre-processing execution.
///
/// Avoiding potential misuse where the user fails to check the pre-processing.
pub struct Output<D: Domain, D2: Domain> {
    result: Vec<D::Scalar>,
    pp_hashes: Vec<Hash>,
    _ph: PhantomData<D2>,
}

impl<D: Domain, D2: Domain> Output<D, D2> {
    pub fn check(self, pp: &preprocessing::Output<D, D2>) -> Option<Vec<D::Scalar>> {
        assert_eq!(pp.hidden.len(), D::ONLINE_REPETITIONS);
        assert_eq!(self.pp_hashes.len(), D::ONLINE_REPETITIONS);
        for i in 0..D::ONLINE_REPETITIONS {
            if pp.hidden[i] != self.pp_hashes[i] {
                return None;
            }
        }
        Some(self.result)
    }

    // provides access to the output without checking the pre-processing
    // ONLY USED IN TESTS: enables testing of the online phase separately from pre-processing
    #[cfg(test)]
    pub(super) fn unsafe_output(&self) -> &[D::Scalar] {
        &self.result[..]
    }
}
