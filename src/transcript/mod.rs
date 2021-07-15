mod prover;
mod verifier;

pub use prover::ProverTranscript;
pub use verifier::VerifierTranscriptOnline;
pub use verifier::VerifierTranscriptPreprocess;

use crate::algebra::Domain;
use crate::crypto::hash::{Hash, Hasher};
use crate::crypto::prg::{Key, KEY_SIZE, PRG};
use crate::generator::ShareGen;
use crate::interpreter::Wire;
use crate::{PACKED, PLAYERS};

pub trait Transcript<D: Domain> {
    const IS_PROVER: bool = false;

    // Different instances:
    //
    // - Proving   : input is the next input value
    // - Verifying : input is unused bogus value a
    fn input(&mut self) -> Wire<D>;

    /// Reconstructs the share:
    ///
    /// # Proving
    ///
    /// The transcript records the mask (each share send by each party)
    ///
    /// # Verifying (Online)
    ///
    /// The transcript adds the missing share for the unopened players
    ///
    /// # Verifying (Preprocessing)
    ///
    /// Nop, just return zero.
    fn reconstruct(&mut self, mask: D::Share) -> D::Recon;

    /// Record correction:
    ///
    /// # Proving
    ///
    /// The transcript records the correction
    ///
    /// # Verifying (Online)
    ///
    /// The transcript provides the next correction (ignoring the input)
    ///
    /// # Verifying (Preprocessing)
    ///
    /// The transcript records the correction
    fn correction(&mut self, corr: D::Recon) -> D::Recon;

    /// Record if the reconstructed value is zero
    ///
    /// # Proving
    ///
    /// Check if zero: if not the witness was invalid and the prover aborts
    ///
    /// # Verifying (Online)
    ///
    /// Check if zero: if zero the proof is invalid.
    ///
    /// # Verifying (Preprocessing)
    ///
    /// Nop. Ignore the input.
    fn zero_check(&mut self, recon: D::Recon);

    fn new_mask(&mut self) -> D::Share;

    /// Return the commitment to the online phase
    fn online_hash(&self) -> [Hash; PACKED];

    /// Return the commitment to the preprocessing phase
    fn preprocess_hash(&self) -> [Hash; PACKED];

    fn hash(&self) -> [Hash; PACKED] {
        fn hash_join(preprocess: &Hash, online: &Hash) -> Hash {
            let mut hasher = Hasher::new();
            hasher.update(preprocess.as_bytes());
            hasher.update(online.as_bytes());
            hasher.finalize()
        }
        let online_hashes = self.online_hash();
        let preprocess_hashes = self.preprocess_hash();
        [
            hash_join(&preprocess_hashes[0], &online_hashes[0]),
            hash_join(&preprocess_hashes[1], &online_hashes[1]),
            hash_join(&preprocess_hashes[2], &online_hashes[2]),
            hash_join(&preprocess_hashes[3], &online_hashes[3]),
            hash_join(&preprocess_hashes[4], &online_hashes[4]),
            hash_join(&preprocess_hashes[5], &online_hashes[5]),
            hash_join(&preprocess_hashes[6], &online_hashes[6]),
            hash_join(&preprocess_hashes[7], &online_hashes[7]),
        ]
    }
}

fn expand_seed(seed: Key) -> [Key; PLAYERS] {
    let mut prg = PRG::new(&seed);
    let mut keys = [[0u8; KEY_SIZE]; PLAYERS];
    for key in keys.iter_mut() {
        prg.gen(key);
    }
    keys
}

fn share_gen_from_rep_seeds<D: Domain>(seeds: &[Key; PACKED]) -> Box<ShareGen<D>> {
    Box::new(ShareGen::new(
        &[
            expand_seed(seeds[0]),
            expand_seed(seeds[1]),
            expand_seed(seeds[2]),
            expand_seed(seeds[3]),
            expand_seed(seeds[4]),
            expand_seed(seeds[5]),
            expand_seed(seeds[6]),
            expand_seed(seeds[7]),
        ],
        [PLAYERS; PACKED],
    ))
}
