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

pub type ProofGF2P8 = Proof<gf2::GF2P8>;

pub type ProofGF2P64 = Proof<gf2::GF2P64>;

pub type ProofGF2P64_64 = Proof<gf2_vec::GF2P64_64>;

pub type ProofGF2P64_85 = Proof<gf2_vec85::GF2P64_85>;

/// Simplified interface for in-memory proofs
/// with pre-processing verified simultaneously with online execution.
#[derive(Deserialize, Serialize)]
pub struct Proof<D: Domain> {
    preprocessing: preprocessing::Proof<D>,
    online: online::Proof<D>,
    chunks: Vec<Vec<u8>>,
}

impl<D: Domain> Proof<D>
where
    D: Serialize,
{
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
}

impl<'de, D: Domain> Proof<D>
where
    D: Deserialize<'de>,
{
    pub fn deserialize(&self, bytes: &'de [u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

impl<D: Domain> Proof<D> {
    async fn new_async(
        bind: Option<Vec<u8>>,
        program: Arc<Vec<Instruction<D::Scalar>>>,
        branches: Arc<Vec<Vec<D::Scalar>>>,
        branch_index: usize,
        witness: Arc<Vec<D::Scalar>>,
    ) -> Self {
        async fn online_proof<D: Domain>(
            send: Sender<Vec<u8>>,
            bind: Option<Vec<u8>>,
            program: Arc<Vec<Instruction<D::Scalar>>>,
            branch_index: usize,
            witness: Arc<Vec<D::Scalar>>,
            pp_output: preprocessing::PreprocessingOutput<D>,
        ) -> Option<online::Proof<D>> {
            let (online, prover) = online::StreamingProver::new(
                bind,
                pp_output,
                branch_index,
                program.clone(),
                witness.clone(),
            )
            .await;
            prover.stream(send, program, witness).await.unwrap();
            Some(online)
        }

        let branches: Vec<&[D::Scalar]> = branches.iter().map(|b| &b[..]).collect();

        // pick global random seed
        let mut seed: [u8; KEY_SIZE] = [0; KEY_SIZE];
        OsRng.fill_bytes(&mut seed);

        // prove preprocessing
        let (preprocessing, pp_output) =
            preprocessing::Proof::new(seed, &branches[..], program.clone());

        // create prover for online phase
        let (send, recv) = bounded(CHANNEL_CAPACITY);
        let prover_task = task::spawn(online_proof(
            send,
            bind,
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
        bind: Option<Vec<u8>>,
        branches: Arc<Vec<Vec<D::Scalar>>>,
        program: Arc<Vec<Instruction<D::Scalar>>>,
    ) -> Result<Vec<D::Scalar>, String> {
        async fn online_verification<D: Domain>(
            bind: Option<Vec<u8>>,
            program: Arc<Vec<Instruction<D::Scalar>>>,
            proof: online::Proof<D>,
            recv: Receiver<Vec<u8>>,
        ) -> Result<online::Output<D>, String> {
            let verifier = online::StreamingVerifier::new(program, proof);
            verifier.verify(bind, recv).await
        }

        async fn preprocessing_verification<D: Domain>(
            branches: Arc<Vec<Vec<D::Scalar>>>,
            program: Arc<Vec<Instruction<D::Scalar>>>,
            proof: preprocessing::Proof<D>,
        ) -> Option<preprocessing::Output<D>> {
            let branches: Vec<&[D::Scalar]> = branches.iter().map(|b| &b[..]).collect();
            proof.verify(&branches[..], program).await
        }

        // verify pre-processing
        let preprocessing_task = task::spawn(preprocessing_verification(
            branches.clone(),
            program.clone(),
            self.preprocessing.clone(),
        ));

        // verify the online execution
        let (send, recv) = bounded(CHANNEL_CAPACITY);
        let task_online = task::spawn(online_verification(
            bind,
            program,
            self.online.clone(),
            recv,
        ));

        // send proof to the online verifier
        for chunk in self.chunks.clone().into_iter() {
            if let Err(_e) = send.send(chunk).await {
                return Err(String::from("Failed to send chunk to the verifier"));
            }
        }

        // check that online execution matches preprocessing (executing both in parallel)
        let preprocessed = preprocessing_task
            .await
            .ok_or_else(|| String::from("Preprocessing task Failed"))?;
        match task_online.await {
            Ok(out) => Ok(out.check(&preprocessed).ok_or_else(|| {
                String::from("Online task output did not match preprocessing output")
            })?),
            Err(_e) => Err(String::from("Online verification task failed")),
        }
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
        bind: Option<Vec<u8>>,
        program: Vec<Instruction<D::Scalar>>,
        branches: Vec<Vec<D::Scalar>>,
        witness: Vec<D::Scalar>,
        branch_index: usize,
    ) -> Self {
        task::block_on(Self::new_async(
            bind,
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
        bind: Option<Vec<u8>>,
        program: Vec<Instruction<D::Scalar>>,
        branches: Vec<Vec<D::Scalar>>,
    ) -> Result<Vec<D::Scalar>, String> {
        task::block_on(self.verify_async(bind, Arc::new(branches), Arc::new(program)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::gf2::*;
    use crate::algebra::gf2_vec::GF2P64_64;
    use crate::algebra::gf2_vec85::GF2P64_85;
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
        let length = 1 + rng.gen::<usize>() % 128;
        let memory = 1 + rng.gen::<usize>() % 64;

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
    fn test_proof_gf2p8_regression() {
        let test_vectors: Vec<TestVector<GF2P8>> = vec![
            /*
            TestVector {
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
            },
            TestVector {
                program: vec![
                    Instruction::Input(0),
                    Instruction::Input(1),
                    Instruction::Mul(2, 0, 1),
                    Instruction::Output(2),
                ],
                input: vec![BitScalar::ONE, BitScalar::ONE],
                branches: vec![vec![]],
                branch_index: 0,
            },
            TestVector {
                program: vec![
                    Instruction::Input(0),
                    Instruction::Input(1),
                    Instruction::Mul(2, 0, 1),
                    Instruction::Output(2),
                ],
                input: vec![BitScalar::ZERO, BitScalar::ONE],
                branches: vec![vec![]],
                branch_index: 0,
            },
            */
            TestVector {
                program: vec![
                    Instruction::Input(0),
                    Instruction::Input(2),
                    Instruction::Add(6, 2, 2),
                    Instruction::Mul(2, 6, 6),
                    Instruction::LocalOp(0, 2),
                    Instruction::Output(6),
                    Instruction::Mul(0, 2, 2),
                    Instruction::AddConst(2, 0, BitScalar::ONE),
                    Instruction::LocalOp(1, 2),
                    Instruction::LocalOp(0, 2),
                    Instruction::LocalOp(0, 0),
                    Instruction::Branch(1),
                    Instruction::Input(6),
                    Instruction::Mul(1, 6, 6),
                    Instruction::AddConst(2, 2, BitScalar::ZERO),
                    Instruction::Branch(4),
                    Instruction::Add(5, 0, 2),
                    Instruction::Mul(0, 6, 0),
                    Instruction::Input(2),
                    Instruction::MulConst(5, 1, BitScalar::ONE),
                    Instruction::Output(2),
                ],
                input: vec![
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    BitScalar::ZERO,
                    BitScalar::ZERO,
                ],
                branches: vec![vec![BitScalar::ZERO, BitScalar::ZERO]],
                branch_index: 0,
            },
            TestVector {
                program: vec![
                    Instruction::Input(0),
                    Instruction::Branch(1),
                    Instruction::LocalOp(16, 1),
                    Instruction::AddConst(2, 0, BitScalar::ONE),
                    Instruction::Output(0),
                    Instruction::Add(27, 2, 1),
                    Instruction::AddConst(29, 0, BitScalar::ONE),
                    Instruction::Input(20),
                    Instruction::Add(33, 1, 20),
                    Instruction::Add(17, 27, 1),
                    Instruction::AddConst(24, 17, BitScalar::ZERO),
                    Instruction::MulConst(0, 17, BitScalar::ONE),
                    Instruction::Input(16),
                    Instruction::Input(21),
                    Instruction::Input(14),
                    Instruction::LocalOp(15, 0),
                    Instruction::Mul(18, 16, 2),
                    Instruction::Output(0),
                    Instruction::AddConst(17, 14, BitScalar::ZERO),
                    Instruction::AddConst(18, 33, BitScalar::ONE),
                    Instruction::MulConst(9, 21, BitScalar::ZERO),
                    Instruction::Mul(33, 16, 9),
                    Instruction::Branch(1),
                    Instruction::Branch(16),
                    Instruction::MulConst(23, 20, BitScalar::ONE),
                    Instruction::Branch(9),
                    Instruction::Input(20),
                    Instruction::Output(16),
                    Instruction::Branch(13),
                    Instruction::Mul(30, 14, 24),
                    Instruction::Mul(28, 24, 16),
                    Instruction::Branch(22),
                    Instruction::MulConst(32, 27, BitScalar::ONE),
                    Instruction::Branch(22),
                    Instruction::Branch(13),
                    Instruction::Branch(28),
                    Instruction::Output(9),
                    Instruction::LocalOp(19, 0),
                    Instruction::AddConst(6, 28, BitScalar::ZERO),
                    Instruction::AddConst(27, 17, BitScalar::ZERO),
                    Instruction::MulConst(13, 22, BitScalar::ZERO),
                    Instruction::Mul(13, 13, 30),
                    Instruction::Branch(22),
                    Instruction::AddConst(33, 6, BitScalar::ONE),
                    Instruction::Branch(29),
                    Instruction::Input(17),
                    Instruction::MulConst(31, 33, BitScalar::ONE),
                    Instruction::Mul(14, 9, 29),
                    Instruction::Branch(28),
                    Instruction::Branch(33),
                    Instruction::MulConst(34, 24, BitScalar::ZERO),
                    Instruction::MulConst(12, 27, BitScalar::ONE),
                    Instruction::Branch(22),
                    Instruction::Add(12, 29, 20),
                    Instruction::Branch(26),
                    Instruction::MulConst(9, 30, BitScalar::ONE),
                    Instruction::LocalOp(28, 33),
                    Instruction::Branch(23),
                    Instruction::Add(5, 14, 28),
                    Instruction::Mul(24, 23, 0),
                ],
                input: vec![
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    BitScalar::ZERO,
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    BitScalar::ONE,
                    BitScalar::ZERO,
                ],
                branches: vec![vec![
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    BitScalar::ONE,
                    BitScalar::ONE,
                    BitScalar::ONE,
                    BitScalar::ONE,
                    BitScalar::ONE,
                    BitScalar::ONE,
                    BitScalar::ONE,
                    BitScalar::ONE,
                    BitScalar::ONE,
                    BitScalar::ONE,
                ]],
                branch_index: 0,
            },
            TestVector {
                program: vec![
                    Instruction::Input(0),
                    Instruction::Output(0),
                    Instruction::MulConst(156, 0, BitScalar::ZERO),
                    Instruction::Input(85),
                    Instruction::Branch(161),
                    Instruction::LocalOp(63, 0),
                    Instruction::LocalOp(60, 161),
                    Instruction::AddConst(101, 161, BitScalar::ZERO),
                    Instruction::Branch(45),
                    Instruction::Add(58, 156, 156),
                    Instruction::LocalOp(36, 85),
                    Instruction::Mul(82, 45, 156),
                    Instruction::Input(12),
                    Instruction::AddConst(77, 58, BitScalar::ONE),
                    Instruction::Input(57),
                    Instruction::Add(12, 0, 85),
                    Instruction::MulConst(76, 156, BitScalar::ONE),
                    Instruction::LocalOp(46, 161),
                    Instruction::Mul(36, 12, 161),
                    Instruction::MulConst(58, 58, BitScalar::ZERO),
                    Instruction::MulConst(150, 0, BitScalar::ONE),
                    Instruction::Add(65, 58, 76),
                    Instruction::MulConst(28, 58, BitScalar::ONE),
                    Instruction::AddConst(21, 45, BitScalar::ONE),
                    Instruction::MulConst(72, 161, BitScalar::ONE),
                    Instruction::MulConst(9, 12, BitScalar::ZERO),
                    Instruction::AddConst(75, 58, BitScalar::ONE),
                    Instruction::Input(195),
                    Instruction::Branch(66),
                    Instruction::Branch(68),
                    Instruction::LocalOp(82, 85),
                    Instruction::AddConst(197, 150, BitScalar::ONE),
                    Instruction::AddConst(71, 21, BitScalar::ONE),
                    Instruction::AddConst(71, 58, BitScalar::ONE),
                    Instruction::MulConst(210, 28, BitScalar::ONE),
                    Instruction::Input(39),
                    Instruction::Mul(168, 77, 57),
                    Instruction::Mul(174, 58, 12),
                    Instruction::AddConst(17, 57, BitScalar::ONE),
                    Instruction::Output(45),
                    Instruction::Add(209, 12, 210),
                    Instruction::Output(12),
                    Instruction::Mul(93, 82, 195),
                    Instruction::Mul(195, 71, 150),
                    Instruction::LocalOp(5, 17),
                    Instruction::Output(58),
                    Instruction::LocalOp(13, 174),
                    Instruction::MulConst(68, 156, BitScalar::ONE),
                    Instruction::LocalOp(9, 101),
                    Instruction::Branch(44),
                    Instruction::LocalOp(54, 195),
                    Instruction::Input(211),
                    Instruction::AddConst(28, 58, BitScalar::ZERO),
                    Instruction::Branch(168),
                    Instruction::Mul(188, 82, 12),
                    Instruction::Mul(149, 197, 39),
                    Instruction::Branch(184),
                    Instruction::Add(24, 66, 17),
                    Instruction::Input(191),
                    Instruction::MulConst(106, 188, BitScalar::ZERO),
                    Instruction::MulConst(102, 21, BitScalar::ZERO),
                    Instruction::LocalOp(129, 0),
                    Instruction::Add(59, 93, 149),
                    Instruction::Add(170, 150, 58),
                    Instruction::Mul(68, 58, 75),
                    Instruction::MulConst(203, 76, BitScalar::ONE),
                    Instruction::MulConst(111, 76, BitScalar::ONE),
                    Instruction::MulConst(24, 93, BitScalar::ONE),
                    Instruction::Mul(73, 209, 68),
                    Instruction::Mul(174, 39, 174),
                    Instruction::Branch(186),
                    Instruction::Branch(133),
                    Instruction::Add(127, 21, 39),
                    Instruction::LocalOp(182, 106),
                    Instruction::AddConst(27, 93, BitScalar::ZERO),
                    Instruction::AddConst(158, 188, BitScalar::ONE),
                    Instruction::LocalOp(14, 170),
                    Instruction::Input(86),
                    Instruction::Branch(155),
                    Instruction::Branch(81),
                    Instruction::Input(94),
                    Instruction::MulConst(168, 9, BitScalar::ONE),
                    Instruction::Branch(63),
                    Instruction::Output(150),
                    Instruction::Mul(62, 66, 106),
                    Instruction::Output(71),
                    Instruction::AddConst(188, 210, BitScalar::ZERO),
                    Instruction::Mul(19, 59, 170),
                    Instruction::AddConst(97, 195, BitScalar::ONE),
                    Instruction::Add(36, 24, 62),
                    Instruction::Branch(184),
                    Instruction::Output(63),
                    Instruction::Branch(145),
                    Instruction::LocalOp(179, 58),
                    Instruction::Input(179),
                    Instruction::Add(212, 75, 57),
                    Instruction::Add(162, 12, 45),
                    Instruction::Input(147),
                    Instruction::Add(149, 62, 174),
                    Instruction::Output(197),
                    Instruction::Output(85),
                    Instruction::Input(164),
                    Instruction::LocalOp(201, 76),
                    Instruction::Input(156),
                    Instruction::Output(161),
                    Instruction::Input(78),
                    Instruction::MulConst(1, 156, BitScalar::ZERO),
                    Instruction::Mul(94, 36, 57),
                    Instruction::AddConst(14, 168, BitScalar::ZERO),
                    Instruction::Add(26, 65, 184),
                    Instruction::Input(11),
                    Instruction::AddConst(71, 101, BitScalar::ONE),
                    Instruction::Add(30, 174, 58),
                    Instruction::AddConst(172, 71, BitScalar::ONE),
                    Instruction::Add(16, 111, 145),
                    Instruction::AddConst(73, 155, BitScalar::ZERO),
                    Instruction::AddConst(144, 97, BitScalar::ONE),
                    Instruction::MulConst(123, 71, BitScalar::ONE),
                    Instruction::Input(125),
                    Instruction::Input(23),
                    Instruction::Add(200, 179, 209),
                    Instruction::Add(123, 30, 197),
                    Instruction::Input(23),
                    Instruction::Mul(22, 200, 26),
                    Instruction::Output(123),
                    Instruction::Output(93),
                ],
                input: vec![
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    BitScalar::ONE,
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    //
                    BitScalar::ZERO,
                    BitScalar::ZERO,
                    BitScalar::ZERO,
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    //
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    BitScalar::ONE,
                    BitScalar::ONE,
                    BitScalar::ONE,
                    //
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    BitScalar::ONE,
                    BitScalar::ZERO,
                ],
                branches: vec![vec![
                    BitScalar::ZERO,
                    BitScalar::ZERO,
                    BitScalar::ZERO,
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    //
                    BitScalar::ONE,
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    //
                    BitScalar::ZERO,
                    BitScalar::ONE,
                    BitScalar::ZERO,
                    BitScalar::ONE,
                ]],
                branch_index: 0,
            },
        ];

        for test in test_vectors.iter() {
            let output = evaluate_program::<GF2P8>(
                &test.program[..],
                &test.input[..],
                &test.branches[test.branch_index][..],
            );
            let proof = ProofGF2P8::new(
                None,
                test.program.clone(),
                test.branches.clone(),
                test.input.clone(),
                test.branch_index,
            );
            let verifier_output = proof
                .verify(None, test.program.clone(), test.branches.clone())
                .unwrap();
            assert_eq!(verifier_output, output);
        }
    }

    // This test takes a while.
    // Running the prover in debug build is very slow.
    #[test]
    fn test_random_proof_gf2p8() {
        for _ in 0..10 {
            let (program, input, branches, branch_index, output) = random_instance::<GF2P8>();
            let proof =
                ProofGF2P8::new(None, program.clone(), branches.clone(), input, branch_index);
            let verifier_output = proof.verify(None, program, branches).unwrap();
            assert_eq!(verifier_output, output);
        }
    }

    // This test takes a while.
    // Running the prover in debug build is very slow.
    #[test]
    fn test_random_proof_gf2p64() {
        for _ in 0..10 {
            let (program, input, branches, branch_index, output) = random_instance::<GF2P64>();
            let proof =
                ProofGF2P64::new(None, program.clone(), branches.clone(), input, branch_index);
            let verifier_output = proof.verify(None, program, branches).unwrap();
            assert_eq!(verifier_output, output);
        }
    }

    // This test takes a while.
    // Running the prover in debug build is very slow.
    #[test]
    fn test_random_proof_gf2p64_64() {
        for _ in 0..10 {
            let (program, input, branches, branch_index, output) = random_instance::<GF2P64_64>();
            let proof =
                ProofGF2P64_64::new(None, program.clone(), branches.clone(), input, branch_index);
            let verifier_output = proof.verify(None, program, branches).unwrap();
            assert_eq!(verifier_output, output);
        }
    }

    // This test takes a while.
    // Running the prover in debug build is very slow.
    #[test]
    fn test_random_proof_gf2p64_85() {
        for _ in 0..10 {
            let (program, input, branches, branch_index, output) = random_instance::<GF2P64_85>();
            let proof =
                ProofGF2P64_85::new(None, program.clone(), branches.clone(), input, branch_index);
            let verifier_output = proof.verify(None, program, branches).unwrap();
            assert_eq!(verifier_output, output);
        }
    }
}
