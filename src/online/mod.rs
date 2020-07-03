pub mod prover;
pub mod verifier;

use crate::crypto::{RingHasher, TreePRF, KEY_SIZE};
use crate::fs::{View, ViewRNG};
use crate::Instruction;

use crate::algebra::{Domain, RingElement, RingModule, Samplable};

use blake3::Hash;
use rand_core::RngCore;

/// Represents the state required to partially re-execute a single repetition of the online phase.
pub struct Run<D: Domain, const N: usize, const NT: usize> {
    wires: Vec<<D::Sharing as RingModule>::Scalar>, // initial wire values (masked witness)
    zero: Vec<D::Batch>,                            // correction shares for player0
    msgs: Vec<D::Batch>,                            // messages broadcast by hidden player
    open: TreePRF<NT>, // PRF used to derive random tapes for the opened players
}

/// A proof of the online phase consists of a collection of runs to amplify soundness.
pub struct Proof<D: Domain, const N: usize, const NT: usize, const R: usize> {
    runs: Vec<Run<D, N, NT>>,
}
