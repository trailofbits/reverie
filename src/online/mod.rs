pub mod prover;
pub mod verifier;

use crate::crypto::{RingHasher, TreePRF, KEY_SIZE};
use crate::fs::{View, ViewRNG};
use crate::pp::Preprocessing;
use crate::util::{VecMap, Writer};
use crate::Instruction;

use crate::algebra::{Domain, RingElement, RingModule, Samplable, Sharing};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::gf2::*;
    use rand::thread_rng;
    use rand_core::RngCore;

    fn test_proof<D: Domain, const N: usize, const NT: usize, const R: usize>(
        program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
        inputs: &[<D::Sharing as RingModule>::Scalar],
    ) {
        let mut rng = thread_rng();
        let mut seeds: [[u8; KEY_SIZE]; R] = [[0; KEY_SIZE]; R];
        for i in 0..R {
            rng.fill_bytes(&mut seeds[i]);
        }

        let proof: Proof<D, N, NT, R> = Proof::new(&seeds, program, inputs);

        assert!(proof.verify(program));
    }

    #[test]
    fn test_online_gf2p8() {
        let program: Vec<Instruction<BitScalar>> = vec![
            Instruction::Mul(8, 0, 1),
            Instruction::Add(9, 0, 1),
            Instruction::Output(8),
            Instruction::Output(9),
        ];

        let inputs: Vec<BitScalar> = vec![
            BitScalar::ONE,  // 0
            BitScalar::ONE,  // 1
            BitScalar::ONE,  // 2
            BitScalar::ONE,  // 3
            BitScalar::ZERO, // 4
            BitScalar::ZERO, // 5
            BitScalar::ZERO, // 6
            BitScalar::ZERO, // 7
        ];
        test_proof::<GF2P8, 8, 8, 1>(&program[..], &inputs[..]);
    }
}
