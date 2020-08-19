pub mod prover;
pub mod verifier;

/*
#[cfg(test)]
mod tests;
*/

use crate::algebra::{Domain, RingElement};
use crate::crypto::{Hash, MerkleSetProof, RingHasher, TreePRF, KEY_SIZE};

use crate::preprocessing;
use crate::Instruction;

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

pub use prover::StreamingProver;
pub use verifier::StreamingVerifier;

#[derive(Debug, Serialize, Deserialize)]
pub struct Chunk {
    corrections: Vec<u8>,
    broadcast: Vec<u8>,
    witness: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Run<D: Domain> {
    open: TreePRF,         // randomness for opened players
    proof: MerkleSetProof, // merkle proof for masked branch
    branch: Vec<u8>,       // masked branch (packed)
    commitment: Hash,      // commitment for hidden preprocessing player
    _ph: PhantomData<D>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<D: Domain> {
    runs: Vec<Run<D>>,
    _ph: PhantomData<D>,
}

/// This ensures that the user can only get access to the output
/// by validating the online execution against a correctly validated and matching pre-processing execution.
///
/// Avoiding potential misuse where the user fails to check the pre-processing.
pub struct Output<D: Domain> {
    result: Vec<D::Scalar>,
    pp_hashes: Vec<Hash>,
}

impl<D: Domain> Output<D> {
    pub fn check(self, pp: &preprocessing::Output<D>) -> Option<Vec<D::Scalar>> {
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
