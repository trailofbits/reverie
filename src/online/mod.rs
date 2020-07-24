pub mod prover;
pub mod verifier;

/*
#[cfg(test)]
mod tests;
*/

use crate::algebra::RingElement;
use crate::crypto::{RingHasher, TreePRF, KEY_SIZE};
use crate::fs::View;
use crate::Instruction;

use blake3::Hash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Chunk {
    corrections: Vec<u8>,
    broadcast: Vec<u8>,
    witness: Vec<u8>,
}

pub struct Run<const R: usize, const N: usize, const NT: usize> {
    commitment: Hash,
    open: TreePRF<NT>,
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

        let (send, recv) = bounded(5);

        task::block_on(p.stream(send));

        loop {
            match recv.try_recv() {
                Ok(v) => println!("{:?}", v),
                Err(_) => break,
            }
        }
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
            Instruction::Output(0),
            Instruction::Output(1),
            Instruction::Output(2),
            Instruction::Output(3),
            Instruction::Output(0),
            Instruction::Output(1),
            Instruction::Output(2),
            Instruction::Output(3),
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
