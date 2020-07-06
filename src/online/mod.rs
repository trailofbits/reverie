pub mod prover;
pub mod verifier;

#[cfg(test)]
mod tests;

use crate::crypto::{RingHasher, TreePRF, KEY_SIZE};
use crate::fs::{View, ViewRNG};
use crate::pp::Preprocessing;
use crate::Instruction;

use crate::algebra::{Domain, RingElement, RingModule};

pub trait Transcript<D: Domain> {
    fn write_multiplication(&mut self, val: D::Sharing);
    fn write_reconstruction(&mut self, val: D::Sharing);
}

pub trait Output<D: Domain> {
    fn hidden_share(&mut self) -> D::Sharing;
}

pub fn shares_to_batches<D: Domain, const N: usize>(
    mut shares: Vec<D::Sharing>,
    idx: usize,
) -> Vec<D::Batch> {
    // pad to multiple of batch dimension
    let num_batches = (shares.len() + D::Batch::DIMENSION - 1) / D::Batch::DIMENSION;
    shares.resize(num_batches * D::Batch::DIMENSION, D::Sharing::ZERO);

    // extract the player batches from D::Batch::DIMENSION player sharings
    let mut batches = Vec::with_capacity(num_batches);
    for i in 0..num_batches {
        let mut batch = [D::Batch::ZERO; N];
        D::convert_inv(
            &mut batch,
            &shares[i * D::Batch::DIMENSION..(i + 1) * D::Batch::DIMENSION],
        );

        #[cfg(test)]
        println!("batches[omitted] = {:?}", batch[idx]);
        batches.push(batch[idx]);
    }
    batches
}

pub fn shares_to_scalar<D: Domain, const N: usize>(
    shares: &[D::Sharing],
    idx: usize,
) -> Vec<<D::Sharing as RingModule>::Scalar> {
    let mut scalars = Vec::with_capacity(shares.len());
    for share in shares {
        scalars.push(share.get(idx))
    }
    scalars
}

/// Represents the state required to partially re-execute a single repetition of the online phase.
pub struct Run<D: Domain, const N: usize, const NT: usize> {
    corrections: Vec<D::Batch>,     // correction shares for player0
    multiplications: Vec<D::Batch>, // messages broadcast by hidden player
    reconstructions: Vec<D::Batch>, //
    inputs: Vec<<D::Sharing as RingModule>::Scalar>, // initial wire values (masked witness)
    open: TreePRF<NT>,              // PRF to derive random tapes for the opened players
}

/// A proof of the online phase consists of a collection of runs to amplify soundness.
pub struct Proof<D: Domain, const N: usize, const NT: usize, const R: usize> {
    runs: Vec<Run<D, N, NT>>,
}
