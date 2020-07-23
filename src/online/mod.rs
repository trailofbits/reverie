pub mod prover;
// pub mod verifier;

/*
#[cfg(test)]
mod tests;
*/

use crate::algebra::{Domain, RingElement, RingModule};
use crate::crypto::{RingHasher, TreePRF, KEY_SIZE};
use crate::fs::{View, ViewRNG};
use crate::Instruction;

use crossbeam::channel::bounded;

use async_std::{fs::File, io, prelude::*, task};
use blake3::Hash;

pub struct Run<const R: usize, const N: usize, const NT: usize> {
    commitment: Hash,
    open: TreePRF<NT>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::thread_rng;
    use rand::Rng;
    use rand_core::RngCore;

    use crate::algebra::gf2::*;
    use crate::preprocessing::PreprocessingOutput;

    fn test_proof<D: Domain, const N: usize, const NT: usize, const R: usize>(
        program: &[Instruction<D::Scalar>],
        inputs: &[D::Scalar],
    ) {
        let mut rng = thread_rng();
        let mut seeds: [[u8; KEY_SIZE]; R] = [[0; KEY_SIZE]; R];
        for i in 0..R {
            rng.fill_bytes(&mut seeds[i]);
        }

        // create a proof of the program execution
        let p: prover::StreamingProver<D, _, _, R, N, NT> =
            task::block_on(prover::StreamingProver::new(
                PreprocessingOutput::dummy(),
                program.iter().cloned(),
                inputs.iter().cloned(),
            ));
    }

    #[test]
    fn test_streaming() {
        let program: Vec<Instruction<BitScalar>> = vec![
            Instruction::Input(0),
            Instruction::Input(1),
            Instruction::Input(2),
            Instruction::Input(3),
            Instruction::Output(0),
            Instruction::Output(1),
            Instruction::Output(2),
            Instruction::Output(3),
        ];

        let inputs: Vec<BitScalar> = vec![
            BitScalar::ONE,
            BitScalar::ZERO,
            BitScalar::ONE,
            BitScalar::ZERO,
        ];

        test_proof::<GF2P8, 8, 8, 1>(&program[..], &inputs[..]);
    }
}
