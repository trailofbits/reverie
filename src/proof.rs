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

pub type ProofGF2P8 = Proof<gf2::GF2P8>;

/// Proof system offering 128-bits of classical (non Post Quantum) security.
/// Proof size is ~ 46 bits / multiplication.
/// The proof generation / verification is roughly 8 times that of ProofGF2P8
///
/// # Example
///
/// Proving that you know bits a, b st. a * b = 1
///

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
        branches: Arc<Vec<Vec<D::Scalar>>>,
        branch_index: usize,
        witness: Arc<Vec<D::Scalar>>,
    ) -> Self {
        async fn online_proof<D: Domain>(
            send: Sender<Vec<u8>>,
            program: Arc<Vec<Instruction<D::Scalar>>>,
            branch_index: usize,
            witness: Arc<Vec<D::Scalar>>,
            pp_output: preprocessing::PreprocessingOutput<D>,
        ) -> Option<online::Proof<D>> {
            let (online, prover) = online::StreamingProver::new(
                pp_output,
                branch_index,
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

        let branches: Vec<&[D::Scalar]> = branches.iter().map(|b| &b[..]).collect();

        // pick global random seed
        let mut seed: [u8; KEY_SIZE] = [0; KEY_SIZE];
        OsRng.fill_bytes(&mut seed);

        // prove preprocessing
        let (preprocessing, pp_output) =
            preprocessing::Proof::new(seed, &branches[..], program.iter().cloned());

        // create prover for online phase
        let (send, recv) = bounded(CHANNEL_CAPACITY);
        let prover_task = task::spawn(online_proof(
            send,
            program.clone(),
            branch_index,
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
        branches: Arc<Vec<Vec<D::Scalar>>>,
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
            branches: Arc<Vec<Vec<D::Scalar>>>,
            program: Arc<Vec<Instruction<D::Scalar>>>,
            proof: preprocessing::Proof<D>,
        ) -> Option<preprocessing::Output<D>> {
            let branches: Vec<&[D::Scalar]> = branches.iter().map(|b| &b[..]).collect();
            proof.verify(&branches[..], program.iter().cloned()).await
        }

        // verify pre-processing
        let preprocessing_task = task::spawn(preprocessing_verification(
            branches.clone(),
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
    pub fn new(
        program: Vec<Instruction<D::Scalar>>,
        branches: Vec<Vec<D::Scalar>>,
        witness: Vec<D::Scalar>,
        branch_index: usize,
    ) -> Self {
        task::block_on(Self::new_async(
            Arc::new(program),
            Arc::new(branches),
            branch_index,
            Arc::new(witness),
        ))
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
    pub fn verify(
        &self,
        program: Vec<Instruction<D::Scalar>>,
        branches: Vec<Vec<D::Scalar>>,
    ) -> Option<Vec<D::Scalar>> {
        task::block_on(self.verify_async(Arc::new(branches), Arc::new(program)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::gf2::*;
    use crate::tests::*;

    use rand::thread_rng;
    use rand::Rng;

    #[derive(Debug, Clone)]
    struct TestVector<D: Domain> {
        input: Vec<D::Scalar>,
        program: Vec<Instruction<D::Scalar>>,
        branches: Vec<Vec<D::Scalar>>,
        branch_index: usize,
    }

    fn random_instance<D: Domain>() -> (
        Vec<Instruction<D::Scalar>>, // program
        Vec<D::Scalar>,              // input
        Vec<Vec<D::Scalar>>,         // branches
        usize,                       // branch
        Vec<D::Scalar>,              // result
    ) {
        let mut rng = thread_rng();
        let length = rng.gen::<usize>() % 1024;
        let memory = rng.gen::<usize>() % 2048;

        let length = 10;
        let memory = 32;

        let (num_inputs, num_branch, program) = random_program::<D, _>(&mut rng, length, memory);
        let input = random_scalars::<D, _>(&mut rng, num_inputs);
        let num_branches = 1 + rng.gen::<usize>() % 32;

        let mut branches: Vec<Vec<D::Scalar>> = Vec::with_capacity(num_branches);
        for _ in 0..num_branches {
            branches.push(random_scalars::<D, _>(&mut rng, num_branch));
        }

        let branch_index = rng.gen::<usize>() % num_branches;

        let output = evaluate_program::<D>(&program[..], &input[..], &branches[branch_index][..]);

        (program, input, branches, branch_index, output)
    }

    #[test]
    fn test_random_proof_gf2p8_regression() {
        let test_vectors: Vec<TestVector<GF2P8>> = vec![TestVector {
            program: vec![
                Instruction::Input(0),
                Instruction::Add(25, 0, 0),
                Instruction::Branch(22),
                Instruction::Add(28, 25, 0),
                Instruction::Add(22, 28, 28),
                Instruction::Input(22),
                Instruction::Branch(11),
                Instruction::Output(28),
            ],
            input: vec![BitScalar::ONE, BitScalar::ZERO],
            branches: vec![vec![BitScalar::ONE, BitScalar::ONE]],
            branch_index: 0,
        }];

        for test in test_vectors.iter() {
            let output = evaluate_program::<GF2P8>(
                &test.program[..],
                &test.input[..],
                &test.branches[test.branch_index][..],
            );
            let proof = ProofGF2P8::new(
                test.program.clone(),
                test.branches.clone(),
                test.input.clone(),
                test.branch_index,
            );
            let verifier_output = proof
                .verify(test.program.clone(), test.branches.clone())
                .unwrap();
            assert_eq!(verifier_output, output);
        }
    }

    #[test]
    fn test_random_proof_gf2p8() {
        for _ in 0..50 {
            let (program, input, branches, branch_index, output) = random_instance::<GF2P8>();

            println!("{:?}", program);
            let proof = ProofGF2P8::new(program.clone(), branches.clone(), input, branch_index);
            let verifier_output = proof.verify(program, branches).unwrap();
            assert_eq!(verifier_output, output);
        }
    }

    #[test]
    fn test_proof() {
        let program: Vec<Instruction<BitScalar>> = vec![
            Instruction::Branch(0),
            Instruction::Input(1),
            Instruction::Mul(2, 0, 1),
            Instruction::Output(2),
        ];
        let branches: Vec<Vec<BitScalar>> = vec![vec![BitScalar::ONE], vec![BitScalar::ZERO]];
        let witness: Vec<BitScalar> = vec![BitScalar::ONE];
        let branch_index: usize = 0;
        let proof = ProofGF2P8::new(program.clone(), branches.clone(), witness, branch_index);

        let output = proof.verify(program, branches).unwrap();
        println!("{:?}", output);
    }
}
