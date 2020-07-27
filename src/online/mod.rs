pub mod prover;
pub mod verifier;

/*
#[cfg(test)]
mod tests;
*/

use crate::algebra::{Domain, RingElement};
use crate::crypto::{RingHasher, TreePRF, KEY_SIZE};
use crate::fs::View;
use crate::util::Array;
use crate::Instruction;

use std::marker::PhantomData;

use blake3::Hash;
use serde::{Deserialize, Serialize};

pub use prover::StreamingProver;
pub use verifier::StreamingVerifier;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chunk {
    corrections: Vec<u8>,
    broadcast: Vec<u8>,
    witness: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Run<const R: usize, const N: usize, const NT: usize> {
    commitment: [u8; 32],
    open: TreePRF<NT>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<D: Domain, const R: usize, const N: usize, const NT: usize> {
    runs: Array<Run<R, N, NT>, R>,
    chunk_size: usize,
    _ph: PhantomData<D>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_channel::bounded;
    use async_std::task;

    use rand::thread_rng;
    use rand_core::RngCore;

    use crate::algebra::gf2::*;
    use crate::algebra::Domain;
    use crate::preprocessing::PreprocessingOutput;

    /*
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
        let (proof, p): (_, prover::StreamingProver<D, _, _, R, N, NT>) =
            prover::StreamingProver::new(
                PreprocessingOutput::dummy(),
                program.iter().cloned(),
                inputs.iter().cloned(),
            );

        let (send, recv) = bounded(5);

        task::block_on(p.stream(send)).unwrap();

        let v = verifier::StreamingVerifier::new(program.iter().cloned(), proof);

        task::block_on(v.verify(recv)).unwrap();
    }

    #[test]
    fn test_streaming() {
        let program: Vec<Instruction<BitScalar>> = vec![
            Instruction::Input(0),
            Instruction::Input(1),
            Instruction::Input(2),
            Instruction::Input(3),
            Instruction::Add(5, 0, 1), // 1
            Instruction::Mul(4, 5, 2), // 1
            Instruction::Output(4),
            Instruction::Output(5),
        ];

        let inputs: Vec<BitScalar> = vec![
            BitScalar::ONE,
            BitScalar::ZERO,
            BitScalar::ONE,
            BitScalar::ZERO,
        ];

        test_proof::<GF2P8, 8, 8, 1>(&program[..], &inputs[..]);
    }
    */
}
