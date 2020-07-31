use crate::algebra::*;
use crate::crypto::KEY_SIZE;
use crate::online;
use crate::preprocessing;
use crate::Instruction;

use rand::rngs::OsRng;
use rand_core::RngCore;

use async_channel::{bounded, Receiver, Sender};
use async_std::task;

use serde::{Deserialize, Serialize};

use std::sync::Arc;

const CHANNEL_CAPACITY: usize = 100;

/// Proof system offering 128-bits of classical (non Post Quantum) security.
/// Proof size is ~ 88 bits / multiplication.
///
/// # Example
///
/// Proving that you know bits a, b st. a * b = 1
///
/// ```
/// use reverie::Instruction;
/// use reverie::ProofGF2P8;
/// use reverie::algebra::gf2::*;
///
/// // result of satisfying witness
/// let result = vec![BIT1];
///
/// // inputs (the witness)
/// let witness = vec![BIT1, BIT1];
///
/// // the program (circuit description)
/// let program: Vec<Instruction<BitScalar>> = vec![
///     Instruction::Input(0),     // w[0] <- 0: assign w[0] the next bit from the witness
///     Instruction::Input(1),     // w[1] <- 1: assign w[1] the next bit from the witness
///     Instruction::Mul(2, 0, 1), // w[2] <- w[0] * w[1]
///     Instruction::Output(2)     // output the value of w[2]
/// ];
///
/// // generate a proof (proof implements serde Serialize / Deserialize)
/// let proof = ProofGF2P8::new(program.clone(), witness.clone());
///
/// // verify the proof (in production you should check the result)
/// let output = proof.verify(program).unwrap();
///
/// assert_eq!(&output[..], &result[..]);
/// ```
pub type ProofGF2P8 = Proof<gf2::GF2P8>;

/// Proof system offering 128-bits of classical (non Post Quantum) security.
/// Proof size is ~ 46 bits / multiplication.
/// The proof generation / verification is roughly 8 times that of ProofGF2P8
///
/// # Example
///
/// Proving that you know bits a, b st. a * b = 1
///
/// ```
/// use reverie::Instruction;
/// use reverie::ProofGF2P64;
/// use reverie::algebra::gf2::*;
///
/// // result of satisfying witness
/// let result = vec![BIT1];
///
/// // inputs (the witness)
/// let witness = vec![BIT1, BIT1];
///
/// // the program (circuit description)
/// let program: Vec<Instruction<BitScalar>> = vec![
///     Instruction::Input(0),     // w[0] <- 0: assign w[0] the next bit from the witness
///     Instruction::Input(1),     // w[1] <- 1: assign w[1] the next bit from the witness
///     Instruction::Mul(2, 0, 1), // w[2] <- w[0] * w[1]
///     Instruction::Output(2)     // output the value of w[2]
/// ];
///
/// // generate a proof (proof implements serde Serialize / Deserialize)
/// let proof = ProofGF2P64::new(program.clone(), witness.clone());
///
/// // verify the proof (in production you should check the result)
/// let output = proof.verify(program).unwrap();
///
/// assert_eq!(&output[..], &result[..]);
/// ```
pub type ProofGF2P64 = Proof<gf2::GF2P64>;

/// Simplified interface for in-memory proofs
/// with pre-processing verified simultaneously with online execution.
#[derive(Deserialize, Serialize)]
pub struct Proof<D: Domain> {
    preprocessing: preprocessing::Proof<D>,
    online: online::Proof<D>,
    chunks: Vec<Vec<u8>>,
}

impl<D: Domain> Proof<D> {
    async fn new_async(
        program: Arc<Vec<Instruction<D::Scalar>>>,
        witness: Arc<Vec<D::Scalar>>,
    ) -> Self {
        async fn online_proof<D: Domain>(
            send: Sender<Vec<u8>>,
            program: Arc<Vec<Instruction<D::Scalar>>>,
            witness: Arc<Vec<D::Scalar>>,
            pp_output: preprocessing::PreprocessingOutput<D>,
        ) -> Option<online::Proof<D>> {
            let (online, prover) = online::StreamingProver::new(
                pp_output,
                program.clone().iter().cloned(),
                witness.clone().iter().cloned(),
            )
            .await;
            prover
                .stream(send, program.iter().cloned(), witness.iter().cloned())
                .await
                .unwrap();
            Some(online)
        }

        // pick global random seed
        let mut seed: [u8; KEY_SIZE] = [0; KEY_SIZE];
        OsRng.fill_bytes(&mut seed);

        // prove preprocessing
        let (preprocessing, pp_output) = preprocessing::Proof::new(seed, program.iter().cloned());

        // create prover for online phase
        let (send, recv) = bounded(CHANNEL_CAPACITY);
        let prover_task = task::spawn(online_proof(
            send,
            program.clone(),
            witness.clone(),
            pp_output,
        ));

        // read all chunks from online execution
        let mut chunks = Vec::with_capacity(D::ONLINE_REPETITIONS);
        while let Ok(chunk) = recv.recv().await {
            chunks.push(chunk)
        }

        // should never fail
        Proof {
            preprocessing,
            online: prover_task.await.unwrap(),
            chunks,
        }
    }

    async fn verify_async(
        &self,
        program: Arc<Vec<Instruction<D::Scalar>>>,
    ) -> Option<Vec<D::Scalar>> {
        async fn online_verification<D: Domain>(
            program: Arc<Vec<Instruction<D::Scalar>>>,
            proof: online::Proof<D>,
            recv: Receiver<Vec<u8>>,
        ) -> Option<online::Output<D>> {
            let verifier = online::StreamingVerifier::new(program.iter().cloned(), proof);
            verifier.verify(recv).await
        }

        async fn preprocessing_verification<D: Domain>(
            program: Arc<Vec<Instruction<D::Scalar>>>,
            proof: preprocessing::Proof<D>,
        ) -> Option<preprocessing::Output<D>> {
            proof.verify(program.iter().cloned()).await
        }

        // verify pre-processing
        let preprocessing_task = task::spawn(preprocessing_verification(
            program.clone(),
            self.preprocessing.clone(),
        ));

        // verify the online execution
        let (send, recv) = bounded(CHANNEL_CAPACITY);
        let task_online = task::spawn(online_verification(program, self.online.clone(), recv));

        // send proof to the online verifier
        for chunk in self.chunks.clone().into_iter() {
            send.send(chunk).await.ok()?;
        }

        // check that online execution matches preprocessing (executing both in parallel)
        task_online.await?.check(&preprocessing_task.await?)
    }

    /// Create a new proof for the correct execution of program(witness)
    ///
    /// Note that there is no notion of the witness "satisfying" the program,
    /// rather we produce a proof that "program(witness)" results in the particular output.
    /// This allows e.g. the computation of y = SHA-256(x) with y being output to the verifier,
    /// without the need for an equality check inside the program.
    ///
    /// If the "program" is not well-formed, the behavior is undefined (but safe).
    /// In particular accessing an unassigned wire might cause a panic.
    /// If "witness" is too short for the program, this causes a panic.
    ///
    /// # Arguments
    ///
    /// - `program`: A slice of instructions (including input gates).
    /// - `witness`: The input to the program (length matching the number of input gates)
    ///
    /// # Output
    ///
    /// A stand alone proof for both online and preprocessing execution.
    pub fn new(program: Vec<Instruction<D::Scalar>>, witness: Vec<D::Scalar>) -> Self {
        task::block_on(Self::new_async(Arc::new(program), Arc::new(witness)))
    }

    /// Verify the a proof and return the output of the program
    ///
    /// # Arguments
    ///
    /// # Output
    ///
    /// If the proof is valid: a vector of scalars from the domain (usually bits),
    /// which is the output of the program run on the witness.
    /// Usually the verifier then checks that the output is some expected constant,
    /// e.g. the vector [1]
    ///
    /// If the proof is invalid: None.
    pub fn verify(&self, program: Vec<Instruction<D::Scalar>>) -> Option<Vec<D::Scalar>> {
        task::block_on(self.verify_async(Arc::new(program)))
    }
}

impl<'de, D: Domain> Proof<D>
where
    D: Deserialize<'de>,
{
    /// Deserialize a byte slice into a proof using bincode
    ///
    /// # Arguments
    ///
    /// - `bytes`: The serialized proof
    ///
    /// # Output
    ///
    /// A proof structure if the serialized proof is well-formed, otherwise None.
    pub fn deserialize(bytes: &'de [u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

impl<'de, D: Domain> Proof<D>
where
    D: Serialize,
{
    /// Serialize the proof into a byte vector using bincode
    /// (which can be sent to the verifier)
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::algebra::gf2::BitScalar;
    use crate::algebra::RingElement;
    use crate::Instruction;

    #[test]
    fn test_gf2p64_simplified() {
        let result = vec![
            <BitScalar as RingElement>::ONE,
            <BitScalar as RingElement>::ONE,
            <BitScalar as RingElement>::ZERO,
            <BitScalar as RingElement>::ONE,
        ];
        let witness = vec![
            <BitScalar as RingElement>::ZERO,
            <BitScalar as RingElement>::ONE,
            <BitScalar as RingElement>::ONE,
        ];
        let program: Vec<Instruction<BitScalar>> = vec![
            Instruction::Input(0),     // v[0] <- 0
            Instruction::Input(1),     // v[1] <- 1
            Instruction::Input(2),     // v[2] <- 1
            Instruction::Output(2),    // <- v[2]
            Instruction::Mul(3, 2, 1), // v[3] <- v[2] * v[1]
            Instruction::Output(3),    // <- v[3]
            Instruction::Add(0, 1, 1), // v[0] <- v[1] + v[1] = 0
            Instruction::Output(0),    // <- v[0]
            Instruction::Add(0, 0, 2), // v[0] <- v[0] + v[2] = 1
            Instruction::Output(0),    // <- v[0]
        ];
        let proof = ProofGF2P64::new(program.clone(), witness);
        let output = proof.verify(program).unwrap();
        assert_eq!(&output[..], &result[..]);
    }

    #[test]
    fn test_gf2p8_simplified() {
        let result = vec![
            <BitScalar as RingElement>::ONE,
            <BitScalar as RingElement>::ONE,
            <BitScalar as RingElement>::ZERO,
            <BitScalar as RingElement>::ONE,
        ];
        let witness = vec![
            <BitScalar as RingElement>::ZERO,
            <BitScalar as RingElement>::ONE,
            <BitScalar as RingElement>::ONE,
        ];
        let program: Vec<Instruction<BitScalar>> = vec![
            Instruction::Input(0),     // v[0] <- 0
            Instruction::Input(1),     // v[1] <- 1
            Instruction::Input(2),     // v[2] <- 1
            Instruction::Output(2),    // <- v[2]
            Instruction::Mul(3, 2, 1), // v[3] <- v[2] * v[1]
            Instruction::Output(3),    // <- v[3]
            Instruction::Add(0, 1, 1), // v[0] <- v[1] + v[1] = 0
            Instruction::Output(0),    // <- v[0]
            Instruction::Add(0, 0, 2), // v[0] <- v[0] + v[2] = 1
            Instruction::Output(0),    // <- v[0]
        ];
        let proof = ProofGF2P8::new(program.clone(), witness);
        let output = proof.verify(program).unwrap();
        assert_eq!(&output[..], &result[..]);
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))]
mod benchmark {
    use super::super::algebra::gf2::*;
    use super::*;

    use test::Bencher;

    const MULT: usize = 1_000_000;

    #[bench]
    fn bench_simple_proof_gen_n8(b: &mut Bencher) {
        let mut program = vec![Instruction::Input(1), Instruction::Input(2)];
        let witness = vec![
            <BitScalar as RingElement>::ZERO,
            <BitScalar as RingElement>::ONE,
            <BitScalar as RingElement>::ONE,
        ];
        program.resize(MULT + 2, Instruction::Mul(0, 1, 2));
        b.iter(|| ProofGF2P64::new(program.clone(), witness.clone()));
    }

    #[bench]
    fn bench_simple_proof_verify_n8(b: &mut Bencher) {
        let mut program = vec![Instruction::Input(1), Instruction::Input(2)];
        let witness = vec![
            <BitScalar as RingElement>::ZERO,
            <BitScalar as RingElement>::ONE,
            <BitScalar as RingElement>::ONE,
        ];
        program.resize(MULT + 2, Instruction::Mul(0, 1, 2));
        let proof = ProofGF2P64::new(program.clone(), witness.clone());
        b.iter(|| proof.verify(program.clone()));
    }
}
