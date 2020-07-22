pub mod prover;
pub mod verifier;

/*
#[cfg(test)]
mod tests;
*/

use crate::algebra::{Domain, RingElement, RingModule};
use crate::crypto::{RingHasher, TreePRF, KEY_SIZE};
use crate::fs::{View, ViewRNG};
use crate::Instruction;

use blake3::Hash;

fn shares_to_batches<D: Domain, const N: usize>(
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
        batches.push(batch[idx]);
    }
    batches
}

/// Represents a chunked portion of a streaming proof
///
/// These are serialized and send over the wire.
pub struct Chunk<D: Domain, const N: usize> {
    multiplication_corrections: Vec<D::Batch>,
    multiplication_recons: Vec<D::Batch>,
    output_recons: Vec<D::Batch>,
    inputs_wire: Vec<D::Batch>,
}

pub struct Run<const R: usize, const N: usize, const NT: usize> {
    commitment: Hash,
    open: TreePRF<NT>,
}
