use crate::algebra::*;
use crate::crypto::KEY_SIZE;
use crate::{online, fieldswitching, ConnectionInstruction};
use crate::preprocessing;
use crate::Instruction;

use rand::rngs::OsRng;
use rand_core::RngCore;

use async_channel::{bounded, Receiver, Sender};
use async_std::task;

use serde::{Deserialize, Serialize};

use std::sync::Arc;
use crate::tests::connection_program;

const CHANNEL_CAPACITY: usize = 100;

pub type FieldSwitching_ProofGF2P8 = Proof<gf2::GF2P8, gf2::GF2P8>;

pub type FieldSwitching_ProofGF2P64 = Proof<gf2::GF2P64, gf2::GF2P64>;

pub type FieldSwitching_ProofGF2P64_64 = Proof<gf2_vec::GF2P64_64, gf2_vec::GF2P64_64>;

pub type FieldSwitching_ProofGF2P64_85 = Proof<gf2_vec85::GF2P64_85, gf2_vec85::GF2P64_85>;

/// Simplified interface for in-memory proofs
/// with pre-processing verified simultaneously with online execution.
#[derive(Deserialize, Serialize)]
pub struct Proof<D: Domain, D2: Domain> {
    preprocessing: fieldswitching::preprocessing::Proof<D, D2>,
    online: fieldswitching::online::Proof<D, D2>,
    chunks: Vec<Vec<u8>>,
}

impl<D: Domain, D2: Domain> Proof<D, D2>
    where
        D: Serialize,
        D2: Serialize,
{
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
}

impl<'de, D: Domain, D2: Domain> Proof<D, D2>
    where
        D: Deserialize<'de>,
        D2: Deserialize<'de>,
{
    pub fn deserialize(&self, bytes: &'de [u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

impl<D: Domain, D2: Domain> Proof<D, D2> {
    async fn new_async(
        bind: Option<Vec<u8>>,
        conn_program: Arc<Vec<ConnectionInstruction>>,
        program1: Arc<Vec<Instruction<D::Scalar>>>,
        program2: Arc<Vec<Instruction<D2::Scalar>>>,
        branches1: Arc<Vec<Vec<D::Scalar>>>,
        branches2: Arc<Vec<Vec<D2::Scalar>>>,
        branch_index: usize,
        witness: Arc<Vec<D::Scalar>>,
    ) -> Self {
        async fn online_proof<D: Domain, D2: Domain>(
            send: Sender<Vec<u8>>,
            bind: Option<Vec<u8>>,
            conn_program: Arc<Vec<ConnectionInstruction>>,
            program1: Arc<Vec<Instruction<D::Scalar>>>,
            program2: Arc<Vec<Instruction<D2::Scalar>>>,
            branch_index: usize,
            witness: Arc<Vec<D::Scalar>>,
            pp_output: fieldswitching::preprocessing::PreprocessingOutput<D, D2>,
        ) -> Option<fieldswitching::online::Proof<D, D2>> {
            let (online, prover) = fieldswitching::online::StreamingProver::new(
                bind.as_ref().map(|x| &x[..]),
                pp_output,
                branch_index,
                conn_program.clone().iter().cloned(),
                witness.clone().iter().cloned(),
            )
                .await;
            prover
                .stream(send, conn_program.iter().cloned(), witness.iter().cloned())
                .await
                .unwrap();
            Some(online)
        }

        let branches1: Vec<&[D::Scalar]> = branches1.iter().map(|b| &b[..]).collect();
        let branches2: Vec<&[D2::Scalar]> = branches2.iter().map(|b| &b[..]).collect();

        // pick global random seed
        let mut seed: [u8; KEY_SIZE] = [0; KEY_SIZE];
        OsRng.fill_bytes(&mut seed);

        // prove preprocessing
        let (preprocessing, pp_output) =
            fieldswitching::preprocessing::Proof::new(seed, &branches1[..], &branches2[..], conn_program.iter().cloned(), program1.iter().cloned(), program2.iter().cloned());

        // create prover for online phase
        let (send, recv) = bounded(CHANNEL_CAPACITY);
        let prover_task = task::spawn(online_proof(
            send,
            bind,
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
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
        branches1: Arc<Vec<Vec<D::Scalar>>>,
        branches2: Arc<Vec<Vec<D2::Scalar>>>,
        conn_program: Arc<Vec<ConnectionInstruction>>,
        program1: Arc<Vec<Instruction<D::Scalar>>>,
        program2: Arc<Vec<Instruction<D2::Scalar>>>,
    ) -> Result<Vec<D::Scalar>, String> {
        async fn online_verification<D: Domain, D2: Domain>(
            bind: Option<Vec<u8>>,
            conn_program: Arc<Vec<ConnectionInstruction>>,
            program1: Arc<Vec<Instruction<D::Scalar>>>,
            program2: Arc<Vec<Instruction<D2::Scalar>>>,
            proof: fieldswitching::online::Proof<D, D2>,
            recv: Receiver<Vec<u8>>,
        ) -> Result<fieldswitching::online::Output<D, D2>, String> {
            let verifier = fieldswitching::online::StreamingVerifier::new(conn_program.iter().cloned(), program1.iter().cloned(),program2.iter().cloned(), proof);
            verifier.verify(bind.as_ref().map(|x| &x[..]), recv).await
        }

        async fn preprocessing_verification<D: Domain, D2: Domain>(
            branches1: Arc<Vec<Vec<D::Scalar>>>,
            branches2: Arc<Vec<Vec<D2::Scalar>>>,
            conn_program: Arc<Vec<ConnectionInstruction>>,
            program1: Arc<Vec<Instruction<D::Scalar>>>,
            program2: Arc<Vec<Instruction<D2::Scalar>>>,
            proof: fieldswitching::preprocessing::Proof<D, D2>,
        ) -> Option<fieldswitching::preprocessing::Output<D, D2>> {
            let branches1: Vec<&[D::Scalar]> = branches1.iter().map(|b| &b[..]).collect();
            let branches2: Vec<&[D2::Scalar]> = branches2.iter().map(|b| &b[..]).collect();
            proof.verify(&branches1[..], &branches2[..], conn_program.iter().cloned(), program1.iter().cloned(), program2.iter().cloned()).await
        }

        // verify pre-processing
        let preprocessing_task = task::spawn(preprocessing_verification(
            branches1.clone(),
            branches2.clone(),
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
            self.preprocessing.clone(),
        ));

        // verify the online execution
        let (send, recv) = bounded(CHANNEL_CAPACITY);
        let task_online = task::spawn(online_verification(
            bind,
            conn_program,
            program1,
            program2,
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
        conn_program: Vec<ConnectionInstruction>,
        program1: Vec<Instruction<D::Scalar>>,
        program2: Vec<Instruction<D2::Scalar>>,
        branches1: Vec<Vec<D::Scalar>>,
        branches2: Vec<Vec<D2::Scalar>>,
        witness: Vec<D::Scalar>,
        branch_index: usize,
    ) -> Self {
        task::block_on(Self::new_async(
            bind,
            Arc::new(conn_program),
            Arc::new(program1),
            Arc::new(program2),
            Arc::new(branches1),
            Arc::new(branches2),
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
        conn_program: Vec<ConnectionInstruction>,
        program1: Vec<Instruction<D::Scalar>>,
        program2: Vec<Instruction<D2::Scalar>>,
        branches1: Vec<Vec<D::Scalar>>,
        branches2: Vec<Vec<D2::Scalar>>,
    ) -> Result<Vec<D::Scalar>, String> {
        task::block_on(self.verify_async(bind, Arc::new(branches1), Arc::new(branches2), Arc::new(conn_program), Arc::new(program1), Arc::new(program2)))
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
}
