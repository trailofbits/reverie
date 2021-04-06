#[cfg(test)]
mod tests {
    use async_std::sync::Arc;
    use async_std::task;
    use rand::rngs::ThreadRng;
    use rand::thread_rng;
    use rand::Rng;

    use crate::algebra::gf2::*;
    use crate::algebra::z64::{Scalar, Z64P8};
    use crate::algebra::*;
    use crate::tests::*;
    use crate::util::eval::{evaluate_fieldswitching_btoa_program, evaluate_program};
    use crate::Instruction;
    use crate::{fieldswitching, ConnectionInstruction};

    #[test]
    fn test_mini_proof_gf2p8() {
        let mut rng = thread_rng();

        let conn_program = connection_program();
        let program1 = Arc::new(mini_program::<Gf2P8>());
        let program2 = Arc::new(mini_program::<Gf2P8>());
        let input = Arc::new(random_scalars::<Gf2P8, ThreadRng>(&mut rng, 4));
        let num_branch = 0;
        let num_branches = 1 + rng.gen::<usize>() % 32;
        let mut branches1: Vec<Vec<BitScalar>> = Vec::with_capacity(num_branches);
        for _ in 0..num_branches {
            branches1.push(random_scalars::<Gf2P8, _>(&mut rng, num_branch));
        }
        let mut branches2: Vec<Vec<BitScalar>> = Vec::with_capacity(num_branches);
        for _ in 0..num_branches {
            branches2.push(random_scalars::<Gf2P8, _>(&mut rng, num_branch));
        }
        let branch_index = rng.gen::<usize>() % num_branches;

        let output = evaluate_fieldswitching_btoa_program::<Gf2P8, Gf2P8>(
            &conn_program[..],
            &program1[..],
            &program2[..],
            &input[..],
            &branches1[branch_index][..],
            &branches2[branch_index][..],
        );
        assert_eq!(input.to_vec(), output);

        let (preprocessed_proof, pp_output) =
            fieldswitching::preprocessing::Proof::<Gf2P8, Gf2P8>::new(
                conn_program.clone(),
                program1.clone(),
                program2.clone(),
                branches1.clone(),
                branches2.clone(),
            );
        let proof = task::block_on(fieldswitching::online::Proof::<Gf2P8, Gf2P8>::new(
            None,
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
            input.clone(),
            branch_index,
            pp_output,
        ));

        let pp_output = task::block_on(preprocessed_proof.verify(
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
            branches1.clone(),
            branches2.clone(),
        ));
        assert!(pp_output.is_ok());
        let verifier_output = task::block_on(proof.verify(
            None,
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
        ))
        .unwrap();
        assert_eq!(verifier_output, output);
    }

    #[test]
    fn test_evaluate_gf2p8_z64() {
        let mut rng = thread_rng();

        let conn_program = connection_program_64();
        let mut program1: Vec<Instruction<BitScalar>> = Vec::new();
        program1.push(Instruction::NrOfWires(128));
        for i in 0..64 {
            program1.push(Instruction::Input(i));
            program1.push(Instruction::AddConst(i + 64, i, BitScalar::ZERO));
            program1.push(Instruction::Output(i + 64));
        }
        let program2 = vec![
            Instruction::NrOfWires(1),
            Instruction::Input(0),
            Instruction::Output(0),
        ];

        let num_branch = 0;
        let num_branches = 1 + rng.gen::<usize>() % 32;
        let mut branches1: Vec<Vec<BitScalar>> = Vec::with_capacity(num_branches);
        for _ in 0..num_branches {
            branches1.push(random_scalars::<Gf2P8, _>(&mut rng, num_branch));
        }
        let mut branches2: Vec<Vec<Scalar>> = Vec::with_capacity(num_branches);
        for _ in 0..num_branches {
            branches2.push(random_scalars::<Z64P8, _>(&mut rng, num_branch));
        }
        let branch_index = rng.gen::<usize>() % num_branches;

        let input = vec![BitScalar::ZERO; 64];
        let output = evaluate_fieldswitching_btoa_program::<Gf2P8, Z64P8>(
            &conn_program[..],
            &program1[..],
            &program2[..],
            &input[..],
            &branches1[branch_index][..],
            &branches2[branch_index][..],
        );
        assert_eq!(output[0], Scalar::ZERO);

        let input = vec![BitScalar::ONE; 64];
        let output = evaluate_fieldswitching_btoa_program::<Gf2P8, Z64P8>(
            &conn_program[..],
            &program1[..],
            &program2[..],
            &input[..],
            &branches1[branch_index][..],
            &branches2[branch_index][..],
        );
        assert_eq!(output[0], Scalar::ZERO - Scalar::ONE);

        let mut input = vec![BitScalar::ZERO; 64];
        input[0] = BitScalar::ONE;
        let output = evaluate_fieldswitching_btoa_program::<Gf2P8, Z64P8>(
            &conn_program[..],
            &program1[..],
            &program2[..],
            &input[..],
            &branches1[branch_index][..],
            &branches2[branch_index][..],
        );
        assert_eq!(output[0], Scalar::ONE);

        let mut input = vec![BitScalar::ZERO; 64];
        input[2] = BitScalar::ONE;
        let output = evaluate_fieldswitching_btoa_program::<Gf2P8, Z64P8>(
            &conn_program[..],
            &program1[..],
            &program2[..],
            &input[..],
            &branches1[branch_index][..],
            &branches2[branch_index][..],
        );
        let four = Scalar::ONE + Scalar::ONE + Scalar::ONE + Scalar::ONE;
        assert_eq!(output[0], four);

        let mut input = vec![BitScalar::ZERO; 64];
        input[3] = BitScalar::ONE;
        let output = evaluate_fieldswitching_btoa_program::<Gf2P8, Z64P8>(
            &conn_program[..],
            &program1[..],
            &program2[..],
            &input[..],
            &branches1[branch_index][..],
            &branches2[branch_index][..],
        );
        assert_eq!(output[0], four + four);

        let mut input = vec![BitScalar::ZERO; 64];
        input[3] = BitScalar::ONE;
        input[0] = BitScalar::ONE;
        let output = evaluate_fieldswitching_btoa_program::<Gf2P8, Z64P8>(
            &conn_program[..],
            &program1[..],
            &program2[..],
            &input[..],
            &branches1[branch_index][..],
            &branches2[branch_index][..],
        );
        assert_eq!(output[0], four + four + Scalar::ONE);
    }

    #[test]
    fn test_mini_proof_gf2p8_z64() {
        let mut rng = thread_rng();

        let conn_program = connection_program_64();
        let program1 = Arc::new(mini_bool_program_64());
        let program2 = Arc::new(mini_arith_program_64());
        let input = Arc::new(random_scalars::<Gf2P8, ThreadRng>(&mut rng, 64));
        let num_branch = 0;
        let num_branches = 1 + rng.gen::<usize>() % 32;
        let mut branches1: Vec<Vec<BitScalar>> = Vec::with_capacity(num_branches);
        for _ in 0..num_branches {
            branches1.push(random_scalars::<Gf2P8, _>(&mut rng, num_branch));
        }
        let mut branches2: Vec<Vec<Scalar>> = Vec::with_capacity(num_branches);
        for _ in 0..num_branches {
            branches2.push(random_scalars::<Z64P8, _>(&mut rng, num_branch));
        }
        let branch_index = rng.gen::<usize>() % num_branches;

        let output = evaluate_fieldswitching_btoa_program::<Gf2P8, Z64P8>(
            &conn_program[..],
            &program1[..],
            &program2[..],
            &input[..],
            &branches1[branch_index][..],
            &branches2[branch_index][..],
        );
        // println!("output: {:?}", output);
        assert_eq!(output[0], output[1]);

        let (preprocessed_proof, pp_output) =
            fieldswitching::preprocessing::Proof::<Gf2P8, Z64P8>::new(
                conn_program.clone(),
                program1.clone(),
                program2.clone(),
                branches1.clone(),
                branches2.clone(),
            );
        let proof = task::block_on(fieldswitching::online::Proof::<Gf2P8, Z64P8>::new(
            None,
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
            input.clone(),
            branch_index,
            pp_output,
        ));

        let pp_output = task::block_on(preprocessed_proof.verify(
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
            branches1.clone(),
            branches2.clone(),
        ));
        assert!(pp_output.is_ok());
        let verifier_output = task::block_on(proof.verify(
            None,
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
        ))
        .unwrap();
        assert_eq!(verifier_output, output);
        assert_eq!(verifier_output[0], verifier_output[1]);
    }

    #[test]
    fn test_straight_arithmetic_passthrough() {
        let mut rng = thread_rng();

        let program1 = Arc::new(mini_random_program_64(&mut rng));
        let conn_program: Vec<ConnectionInstruction> = connection_program_64();
        let program2 = Arc::new(vec![
            Instruction::NrOfWires(1),
            Instruction::Input(0),
            Instruction::Output(0),
        ]);

        let input = Arc::new(random_scalars::<Gf2P8, ThreadRng>(&mut rng, 64));
        let branches1: Vec<Vec<BitScalar>> = vec![vec![]];
        let branches2: Vec<Vec<Scalar>> = vec![vec![]];
        let branch_index = 0;

        let output = evaluate_fieldswitching_btoa_program::<Gf2P8, Z64P8>(
            &conn_program[..],
            &program1[..],
            &program2[..],
            &input[..],
            &branches1[branch_index][..],
            &branches2[branch_index][..],
        );
        // println!("Cleartext output: {:?}", output);

        let (preprocessed_proof, pp_output) =
            fieldswitching::preprocessing::Proof::<Gf2P8, Z64P8>::new(
                conn_program.clone(),
                program1.clone(),
                program2.clone(),
                branches1.clone(),
                branches2.clone(),
            );
        let proof = task::block_on(fieldswitching::online::Proof::<Gf2P8, Z64P8>::new(
            None,
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
            input.clone(),
            branch_index,
            pp_output,
        ));

        let pp_output = task::block_on(preprocessed_proof.verify(
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
            branches1.clone(),
            branches2.clone(),
        ));
        assert!(pp_output.is_ok());
        let verifier_output = task::block_on(proof.verify(
            None,
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
        ))
        .unwrap();
        assert_eq!(verifier_output, output);
    }

    #[test]
    fn test_mini_proof_gf2p8_preprocessing() {
        let mut rng = thread_rng();

        let conn_program = connection_program();
        let program1 = Arc::new(mini_program::<Gf2P8>());
        let program2 = Arc::new(mini_program::<Gf2P8>());
        let num_branch = 0;
        let num_branches = 1 + rng.gen::<usize>() % 32;
        let mut branches: Vec<Vec<BitScalar>> = Vec::with_capacity(num_branches);
        for _ in 0..num_branches {
            branches.push(random_scalars::<Gf2P8, _>(&mut rng, num_branch));
        }

        let (preprocessed_proof, _) = fieldswitching::preprocessing::Proof::<Gf2P8, Gf2P8>::new(
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
            branches.clone(),
            branches.clone(),
        );

        let proof_output = task::block_on(preprocessed_proof.verify(
            conn_program.clone(),
            program1.clone(),
            program2.clone(),
            branches.clone(),
            branches.clone(),
        ));
        assert!(proof_output.is_ok());
    }

    #[test]
    fn test_proof_with_challenge() {
        let mut rng = thread_rng();

        let mut conn_program = connection_program_64();
        conn_program.push(ConnectionInstruction::Challenge(1));
        let mut program1: Vec<Instruction<BitScalar>> = Vec::new();
        program1.push(Instruction::NrOfWires(128));
        for i in 0..64 {
            program1.push(Instruction::Input(i));
            program1.push(Instruction::AddConst(i + 64, i, BitScalar::ZERO));
            program1.push(Instruction::Output(i + 64));
        }
        let program2 = vec![
            Instruction::NrOfWires(2),
            Instruction::Input(0),
            Instruction::Const(1, Scalar::ONE),
            Instruction::Output(0),
            Instruction::Output(1),
        ];

        let input = Arc::new(random_scalars::<Gf2P8, ThreadRng>(&mut rng, 64));
        let num_branch = 0;
        let num_branches = 1 + rng.gen::<usize>() % 32;
        let mut branches1: Vec<Vec<BitScalar>> = Vec::with_capacity(num_branches);
        for _ in 0..num_branches {
            branches1.push(random_scalars::<Gf2P8, _>(&mut rng, num_branch));
        }
        let mut branches2: Vec<Vec<Scalar>> = Vec::with_capacity(num_branches);
        for _ in 0..num_branches {
            branches2.push(random_scalars::<Z64P8, _>(&mut rng, num_branch));
        }
        let branch_index = rng.gen::<usize>() % num_branches;

        let output = evaluate_fieldswitching_btoa_program::<Gf2P8, Z64P8>(
            &conn_program[..],
            &program1[..],
            &program2[..],
            &input[..],
            &branches1[branch_index][..],
            &branches2[branch_index][..],
        );

        let program1_arc = Arc::new(program1);
        let program2_arc = Arc::new(program2);

        let (preprocessed_proof, pp_output) =
            fieldswitching::preprocessing::Proof::<Gf2P8, Z64P8>::new(
                conn_program.clone(),
                program1_arc.clone(),
                program2_arc.clone(),
                branches1.clone(),
                branches2.clone(),
            );
        let proof = task::block_on(fieldswitching::online::Proof::<Gf2P8, Z64P8>::new(
            None,
            conn_program.clone(),
            program1_arc.clone(),
            program2_arc.clone(),
            input.clone(),
            branch_index,
            pp_output,
        ));

        let pp_output = task::block_on(preprocessed_proof.verify(
            conn_program.clone(),
            program1_arc.clone(),
            program2_arc.clone(),
            branches1.clone(),
            branches2.clone(),
        ));
        assert!(pp_output.is_ok());
        let verifier_output = task::block_on(proof.verify(
            None,
            conn_program.clone(),
            program1_arc.clone(),
            program2_arc.clone(),
        ))
        .unwrap();
        assert_eq!(verifier_output[0], output[0]);
        assert_ne!(verifier_output[1], output[1]);
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
    fn adder(
        input1: usize,
        input2: usize,
        carry_in: usize,
        start_new_wires: usize,
    ) -> (usize, usize, Vec<Instruction<BitScalar>>) {
        let mut output = Vec::new();

        output.push(Instruction::Add(start_new_wires, input1, input2)); // input1 and input2 are input bits
        output.push(Instruction::Add(
            start_new_wires + 1,
            carry_in,
            start_new_wires,
        )); // start_new_wires + 1 is S, carry_in is C_in
        output.push(Instruction::Mul(
            start_new_wires + 2,
            carry_in,
            start_new_wires,
        ));
        output.push(Instruction::Mul(start_new_wires + 3, input1, input2));
        output.push(Instruction::Mul(
            start_new_wires + 4,
            start_new_wires + 2,
            start_new_wires + 3,
        ));
        output.push(Instruction::Add(
            start_new_wires + 5,
            start_new_wires + 2,
            start_new_wires + 3,
        ));
        output.push(Instruction::Add(
            start_new_wires + 6,
            start_new_wires + 4,
            start_new_wires + 5,
        )); // start_new_wires+6 is C_out

        (start_new_wires + 1, start_new_wires + 6, output)
    }

    fn first_adder(
        input1: usize,
        input2: usize,
        start_new_wires: usize,
    ) -> (usize, usize, Vec<Instruction<BitScalar>>) {
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
    fn full_adder(
        start_input1: Vec<usize>,
        start_input2: Vec<usize>,
        start_new_wires: usize,
    ) -> (Vec<usize>, usize, Vec<Instruction<BitScalar>>) {
        assert_eq!(start_input1.len(), start_input2.len());
        assert!(start_input1.len() > 0);
        let mut output = Vec::new();
        let mut output_bits = Vec::new();
        let mut start_new_wires_mut = start_new_wires.clone();

        let (mut output_bit, mut carry_out, mut add) =
            first_adder(start_input1[0], start_input2[0], start_new_wires_mut);
        output.append(&mut add);
        output_bits.push(output_bit);
        for i in 1..start_input1.len() {
            start_new_wires_mut = carry_out + 1;
            let (output_bit1, carry_out1, mut add1) = adder(
                start_input1[i],
                start_input2[i],
                carry_out,
                start_new_wires_mut,
            );
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
        let (output_bits, carry_out, mut add_instructions) =
            full_adder(vec![0, 1, 2, 3], vec![4, 5, 6, 7], 8);
        add.append(&mut add_instructions);
        for out in output_bits {
            add.push(Instruction::Output(out));
        }
        add.push(Instruction::Output(carry_out));

        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
            ],
            &[],
            None,
        );
        assert_eq!(
            &output[..],
            &[
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO
            ]
        );
        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
            ],
            &[],
            None,
        );
        assert_eq!(
            &output[..],
            &[
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO
            ]
        );
        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ONE,
            ],
            &[],
            None,
        );
        assert_eq!(
            &output[..],
            &[
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ONE
            ]
        );
        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
            ],
            &[],
            None,
        );
        assert_eq!(
            &output[..],
            &[
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO
            ]
        );
        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ONE,
            ],
            &[],
            None,
        );
        assert_eq!(
            &output[..],
            &[
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ONE
            ]
        );
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

        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[BitScalar::ZERO, BitScalar::ZERO, BitScalar::ZERO],
            &[],
            None,
        );
        assert_eq!(&output[..], &[BitScalar::ZERO, BitScalar::ZERO]);
        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[BitScalar::ZERO, BitScalar::ZERO, BitScalar::ONE],
            &[],
            None,
        );
        assert_eq!(&output[..], &[BitScalar::ONE, BitScalar::ZERO]);
        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[BitScalar::ZERO, BitScalar::ONE, BitScalar::ZERO],
            &[],
            None,
        );
        assert_eq!(&output[..], &[BitScalar::ONE, BitScalar::ZERO]);
        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[BitScalar::ZERO, BitScalar::ONE, BitScalar::ONE],
            &[],
            None,
        );
        assert_eq!(&output[..], &[BitScalar::ZERO, BitScalar::ONE]);
        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[BitScalar::ONE, BitScalar::ZERO, BitScalar::ZERO],
            &[],
            None,
        );
        assert_eq!(&output[..], &[BitScalar::ONE, BitScalar::ZERO]);
        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[BitScalar::ONE, BitScalar::ZERO, BitScalar::ONE],
            &[],
            None,
        );
        assert_eq!(&output[..], &[BitScalar::ZERO, BitScalar::ONE]);
        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[BitScalar::ONE, BitScalar::ONE, BitScalar::ZERO],
            &[],
            None,
        );
        assert_eq!(&output[..], &[BitScalar::ZERO, BitScalar::ONE]);
        let (_wires, output) = evaluate_program::<Gf2P8>(
            &add[..],
            &[BitScalar::ONE, BitScalar::ONE, BitScalar::ONE],
            &[],
            None,
        );
        assert_eq!(&output[..], &[BitScalar::ONE, BitScalar::ONE]);
    }
}
