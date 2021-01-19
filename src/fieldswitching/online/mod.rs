use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

pub use prover::StreamingProver;
pub use verifier::StreamingVerifier;

use crate::algebra::{Domain, RingElement};
use crate::crypto::{Hash, KEY_SIZE, MerkleSetProof, RingHasher, TreePRF};
use crate::Instruction;
use crate::preprocessing;

pub mod prover;
pub mod verifier;

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

/// Online execution "proof header"
///
/// Holds the (constant sized) state required to initialize the streaming online verifier
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<D: Domain> {
    runs: Vec<Run<D>>,
    _ph: PhantomData<D>,
}

impl<D: Domain + Serialize> Proof<D> {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

impl<'de, D: Domain + Deserialize<'de>> Proof<D> {
    pub fn deserialize(encoded: &'de [u8]) -> Option<Self> {
        bincode::deserialize(encoded).ok()
    }
}

/// This struct ensures that the user can only get access to the output (private field)
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
mod test {

    use rand::thread_rng;
    use rand_core::RngCore;

    use crate::{ConnectionInstruction, fieldswitching};
    use crate::algebra::gf2::*;
    use crate::tests::*;
    use async_std::task;

    use super::*;

    fn test_proof<D: Domain, D2: Domain>(
        conn_program: &[ConnectionInstruction],
        program1: &[Instruction<D::Scalar>],
        program2: &[Instruction<D2::Scalar>],
        inputs: &[D::Scalar],
    ) {
        let mut rng = thread_rng();
        const R: usize = 32;
        let mut seeds: [[u8; KEY_SIZE]; R] = [[0; KEY_SIZE]; R];
        for i in 0..R {
            rng.fill_bytes(&mut seeds[i]);
        }

        let branch: Vec<D::Scalar> = vec![];
        let branches: Vec<Vec<D::Scalar>> = vec![branch];
        let branches2: Vec<&[D::Scalar]> = branches.iter().map(|b| &b[..]).collect();

        let branch_2: Vec<D2::Scalar> = vec![];
        let branches_2: Vec<Vec<D2::Scalar>> = vec![branch_2];
        let branches2_2: Vec<&[D2::Scalar]> = branches_2.iter().map(|b| &b[..]).collect();

        for seed in seeds.iter() {
            // let mut proof = Cursor::new(Vec::new());

            // create a proof of the program execution
            let (preprocessing, pp_output) =
                fieldswitching::preprocessing::Proof::<D, D2>::new(*seed, &branches2[..], &branches2_2[..], conn_program.iter().cloned(), program1.iter().cloned(), program2.iter().cloned());
            // proof.write_all(&preprocessing.serialize()[..]);

            // evaluate program in the clear
            let correct_output = evaluate_program::<D>(program1, inputs, &[]);
            // let correct_output = evaluate_program::<D2>(program2, inputs, &[]);

            // extract the output from the proof
            let proof_output = preprocessing.verify(&branches2[..], &branches2_2[..], conn_program.iter().cloned(), program1.iter().cloned(), program2.iter().cloned());

            task::block_on(fieldswitching::online::StreamingProver::<D, D2>::new(
                None,
                pp_output,
                0,
                conn_program.iter().cloned(),
                inputs.iter().cloned(),
            ));
            // proof.write_all(&online.serialize()[..]);

            // verify the online execution
            // let (send, recv) = bounded(100);
            // let task_online =
            //     task::spawn(online::StreamingVerifier::new(program1.rewind()?, online).verify(None, recv));
            //
            // while let Some(vec) = proof.read()? {
            //     send.send(vec).await.unwrap();
            // }
            //
            // mem::drop(send);
            //
            // let online_output = task_online.await.unwrap();
            //
            // assert!(online_output
            //     .check(&pp_output)
            //     .ok_or_else(|| String::from("Online output check failed")).is_ok());
        }
    }

    #[test]
    fn test_online_fieldswitching() {
        let inputs = vec![
            BitScalar::ONE,
            BitScalar::ZERO,
            BitScalar::ZERO,
            BitScalar::ONE,
        ];
        let conn_program = connection_program();
        let program1 = mini_program::<GF2P8>();
        let program2 = mini_program::<GF2P8>();
        test_proof::<GF2P8, GF2P8>(&conn_program[..], &program1[..], &program2[..], &inputs[..]);
    }
}
