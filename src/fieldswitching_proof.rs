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
            let verifier = fieldswitching::online::StreamingVerifier::new(conn_program.iter().cloned(), program1.iter().cloned(), program2.iter().cloned(), proof);
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
            Err(_e) => Err(String::from("Online verification task failed: ") + &*_e),
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
    use rand::rngs::ThreadRng;
    use crate::ProofGF2P8;

    #[test]
    fn test_random_proof_gf2p8() {
        let mut rng = thread_rng();

        let conn_program = connection_program();
        let mut program1 = mini_program::<GF2P8>();
        let mut program2 = mini_program::<GF2P8>();
        let input = random_scalars::<GF2P8, ThreadRng>(&mut rng, 4);
        let num_branch = 0;
        let num_branches = 1 + rng.gen::<usize>() % 32;
        let mut branches: Vec<Vec<BitScalar>> = Vec::with_capacity(num_branches);
        for _ in 0..num_branches {
            branches.push(random_scalars::<GF2P8, _>(&mut rng, num_branch));
        }
        let branch_index = rng.gen::<usize>() % num_branches;

        let output = evaluate_fieldswitching_btoa_program::<GF2P8, GF2P8>(&conn_program[..], &program1[..], &program2[..], &input[..], &input[..], &branches[branch_index][..], &branches[branch_index][..]);

        let mut impacted_output = Vec::new();
        let mut impacted_input = Vec::new();
        for gate in conn_program.clone() {
            match gate {
                ConnectionInstruction::BToA(dst, src) => {
                    impacted_output.push(src.to_vec());
                    impacted_input.push(dst);
                }
                _ => {}
            }
        }
        println!("{:?}", impacted_output);
        println!("{:?}", impacted_input);

        let program1 = prep_circuit1(program1.clone(), impacted_output);
        println!("{:?}", program1);
        let proof1 = ProofGF2P8::new(None, program1.clone(), branches.clone(), input, branch_index);
        let verifier_output1 = proof1.verify(None, program1, branches.clone()).unwrap();

        let mut input2 = Vec::new();
        for gate in conn_program {
            match gate {
                ConnectionInstruction::BToA(dst, src) => {
                    let mut pow_two = BitScalar::ONE;
                    let mut two = BitScalar::ONE + BitScalar::ONE;
                    let mut next = BitScalar::ZERO;
                    for &_src in src.iter() {
                        next = next + verifier_output1[_src - 4] * pow_two;
                        pow_two = two * pow_two;
                    }
                    input2.push(next);
                }
                _ => {}
            }
        }

        let program2 = prep_circuit2(program2.clone(), impacted_input);
        println!("{:?}", program2);
        let proof2 = ProofGF2P8::new(None, program2.clone(), branches.clone(), input2, branch_index);
        let verifier_output2 = proof2.verify(None, program2, branches.clone()).unwrap();


        // let proof =
        //     FieldSwitching_ProofGF2P8::new(None, conn_program.clone(), program1.clone(), program2.clone(), branches.clone(), branches.clone(), input, branch_index);
        // let verifier_output = proof.verify(None, conn_program, program1, program2, branches.clone(), branches).unwrap();
        assert_eq!(verifier_output2, output);
    }

    /// 1 bit adder with carry
    /// Input:
    /// input1: usize               : position of first input
    /// input2: usize               : position of second input
    /// carry_in: usize             : position of carry_in
    /// start_new_wires: usize      : free positions for added wires (start_new_wires, ...)
    ///
    /// Output:
    /// usize                       : position of output bit
    /// usize                       : position of carry out
    /// Vec<Instruction<BitScalar>> : Instruction set for adder with carry based on the given wire values as input.
    fn adder(input1: usize, input2: usize, carry_in: usize, start_new_wires: usize) -> (usize, usize, Vec<Instruction<BitScalar>>) {
        let mut output = Vec::new();

        output.push(Instruction::Add(start_new_wires, input1, input2)); // input1 and input2 are input bits
        output.push(Instruction::Add(start_new_wires + 1, carry_in, start_new_wires)); // start_new_wires + 1 is S, carry_in is C_in
        output.push(Instruction::Mul(start_new_wires + 2, carry_in, start_new_wires));
        output.push(Instruction::Mul(start_new_wires + 3, input1, input2));
        output.push(Instruction::Mul(start_new_wires + 4, start_new_wires + 2, start_new_wires + 3));
        output.push(Instruction::Add(start_new_wires + 5, start_new_wires + 2, start_new_wires + 3));
        output.push(Instruction::Add(start_new_wires + 6, start_new_wires + 4, start_new_wires + 5)); // start_new_wires+6 is C_out

        (start_new_wires + 1, start_new_wires + 6, output)
    }

    fn first_adder(input1: usize, input2: usize, start_new_wires: usize) -> (usize, usize, Vec<Instruction<BitScalar>>) {
        let mut output = Vec::new();

        output.push(Instruction::Add(start_new_wires, input1, input2)); // input1 and input2 are input bits
        output.push(Instruction::Mul(start_new_wires + 1, input1, input2));

        (start_new_wires, start_new_wires + 1, output)
    }

    /// n bit adder with carry
    /// Input:
    /// start_input1: Vec<usize>     : position of the first inputs
    /// start_input2: Vec<usize>     : position of the second inputs (len(start_input1) == len(start_input2))
    /// start_new_wires: usize       : free positions for added wires (start_new_wires, ...)
    ///
    /// Output:
    /// usize                        : position of output bit
    /// usize                        : position of carry out
    /// Vec<Instruction<BitScalar>>  : Instruction set for adder with carry based on the given wire values as input.
    fn full_adder(start_input1: Vec<usize>, start_input2: Vec<usize>, start_new_wires: usize) -> (Vec<usize>, usize, Vec<Instruction<BitScalar>>) {
        assert_eq!(start_input1.len(), start_input2.len());
        assert!(start_input1.len() > 0);
        let mut output = Vec::new();
        let mut output_bits = Vec::new();
        let mut start_new_wires_mut = start_new_wires.clone();

        let (mut output_bit, mut carry_out, mut add) = first_adder(start_input1[0], start_input2[0], start_new_wires);
        output.append(&mut add);
        output_bits.push(output_bit);
        for i in 1..start_input1.len() {
            start_new_wires_mut += carry_out;
            let (output_bit1, carry_out1, mut add1) = adder(start_input1[i], start_input2[i], carry_out, start_new_wires_mut);
            output_bit = output_bit1;
            carry_out = carry_out1;
            output.append(&mut add1);
            output_bits.push(output_bit);
        }

        (output_bits, carry_out, output)
    }

    #[test]
    fn test_full_adder() {
        let mut add = Vec::new();
        add.push(Instruction::Input(0));
        add.push(Instruction::Input(1));
        add.push(Instruction::Input(2));
        add.push(Instruction::Input(3));
        add.push(Instruction::Input(4));
        add.push(Instruction::Input(5));
        add.push(Instruction::Input(6));
        add.push(Instruction::Input(7));
        let (output_bits, carry_out, mut add_instructions) = full_adder(vec![0, 1, 2, 3], vec![4, 5, 6, 7], 8);
        add.append(&mut add_instructions);
        for out in output_bits {
            add.push(Instruction::Output(out));
        }
        add.push(Instruction::Output(carry_out));

        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO], &[]);
        assert_eq!(&output[..], &[BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO]);
        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ONE, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO], &[]);
        assert_eq!(&output[..], &[BitScalar::ONE, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO]);
        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ONE, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ONE, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ONE], &[]);
        assert_eq!(&output[..], &[BitScalar::ONE, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ONE]);
        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ONE, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ONE, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO], &[]);
        assert_eq!(&output[..], &[BitScalar::ZERO, BitScalar::ONE, BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO]);
        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ONE, BitScalar::ONE, BitScalar::ONE, BitScalar::ONE, BitScalar::ONE, BitScalar::ONE, BitScalar::ONE, BitScalar::ONE], &[]);
        assert_eq!(&output[..], &[BitScalar::ZERO, BitScalar::ONE, BitScalar::ONE, BitScalar::ONE, BitScalar::ONE]);
    }

    #[test]
    fn test_adder() {
        let mut add = Vec::new();
        add.push(Instruction::Input(0));
        add.push(Instruction::Input(1));
        add.push(Instruction::Input(2));
        let (output_bit, carry_out, mut add_instructions) = adder(0, 1, 2, 3);
        add.append(&mut add_instructions);
        add.push(Instruction::Output(output_bit));
        add.push(Instruction::Output(carry_out));

        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO], &[]);
        assert_eq!(&output[..], &[BitScalar::ZERO, BitScalar::ZERO]);
        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ZERO, BitScalar::ZERO, BitScalar::ONE], &[]);
        assert_eq!(&output[..], &[BitScalar::ONE, BitScalar::ZERO]);
        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ZERO, BitScalar::ONE, BitScalar::ZERO], &[]);
        assert_eq!(&output[..], &[BitScalar::ONE, BitScalar::ZERO]);
        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ZERO, BitScalar::ONE, BitScalar::ONE], &[]);
        assert_eq!(&output[..], &[BitScalar::ZERO, BitScalar::ONE]);
        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ONE, BitScalar::ZERO, BitScalar::ZERO], &[]);
        assert_eq!(&output[..], &[BitScalar::ONE, BitScalar::ZERO]);
        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ONE, BitScalar::ZERO, BitScalar::ONE], &[]);
        assert_eq!(&output[..], &[BitScalar::ZERO, BitScalar::ONE]);
        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ONE, BitScalar::ONE, BitScalar::ZERO], &[]);
        assert_eq!(&output[..], &[BitScalar::ZERO, BitScalar::ONE]);
        let (_wires, output) = evaluate_program::<GF2P8>(&add[..], &[BitScalar::ONE, BitScalar::ONE, BitScalar::ONE], &[]);
        assert_eq!(&output[..], &[BitScalar::ONE, BitScalar::ONE]);
    }

    fn prep_circuit1(circuit: Vec<Instruction<BitScalar>>, impacted_output: Vec<Vec<usize>>) -> Vec<Instruction<BitScalar>> {
        let mut nr_of_wires_mut = 0;
        let mut out = Vec::new();
        let mut impacted_outs_done = Vec::new();
        for gate in circuit {
            match gate {
                Instruction::NrOfWires(nr_of_wires) => {
                    nr_of_wires_mut = nr_of_wires;
                }
                Instruction::Output(src) => {
                    assert_ne!(nr_of_wires_mut, 0);
                    let mut found = false;
                    for imp_out in impacted_output.clone() {
                        if imp_out.contains(&src) {
                            found = true;
                            if !impacted_outs_done.contains(&src) {
                                impacted_outs_done.append(&mut imp_out.clone());
                                let mut zeroes = Vec::new();
                                for ins in imp_out.clone() {
                                    out.push(Instruction::Const(nr_of_wires_mut, BitScalar::ZERO));
                                    zeroes.push(nr_of_wires_mut);
                                    nr_of_wires_mut += 1;
                                }
                                let (outputs, carry_out, mut add_instructions) = full_adder(imp_out, zeroes, nr_of_wires_mut);
                                nr_of_wires_mut = carry_out;
                                out.append(&mut add_instructions);
                                for outs in outputs {
                                    out.push(Instruction::Output(outs));
                                }
                            }
                            break;
                        }
                    }
                    if !found {
                        out.push(gate);
                    }
                }
                _ => {
                    assert_ne!(nr_of_wires_mut, 0);
                    out.push(gate);
                }
            }
        }
        return out;
    }

    fn prep_circuit2(circuit: Vec<Instruction<BitScalar>>, impacted_input: Vec<usize>) -> Vec<Instruction<BitScalar>> {
        let mut nr = 0;
        let mut out = Vec::new();
        for gate in circuit.clone() {
            match gate {
                Instruction::NrOfWires(nr_of_wires) => {
                    nr = nr_of_wires;
                }
                Instruction::Input(dst) => {
                    assert_ne!(nr, 0);
                    if impacted_input.contains(&dst) {
                        nr += 1;
                        out.push(Instruction::Input(nr));
                        out.push(Instruction::AddConst(dst, nr, BitScalar::ZERO)); //TODO: subtract constant
                    } else {
                        out.push(gate);
                    }
                }
                _ => {
                    assert_ne!(nr, 0);
                    out.push(gate);
                }
            }
        }
        return out;
    }
}
