pub mod prover;
// pub mod verifier;

/*
#[cfg(test)]
mod tests;
*/

use crate::algebra::{Domain, RingElement};
use crate::crypto::{Hash, RingHasher, TreePRF, KEY_SIZE};
use crate::fs::View;
use crate::preprocessing;
use crate::Instruction;

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

pub use prover::StreamingProver;
// pub use verifier::StreamingVerifier;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chunk {
    corrections: Vec<u8>,
    broadcast: Vec<u8>,
    witness: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Run<D: Domain> {
    commitment: Hash,
    open: TreePRF,
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
