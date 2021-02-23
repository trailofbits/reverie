use crate::algebra::*;
use crate::util::VecMap;
use crate::{ConnectionInstruction, Instruction};

use crate::algebra::gf2::{BitScalar, Gf2P8};
use crate::algebra::z64::{Scalar, Z64P8};
use rand::RngCore;
use rand::{thread_rng, Rng};

pub fn random_scalar<D: Domain, R: RngCore>(rng: &mut R) -> D::Scalar {
    let mut share = vec![D::Sharing::ZERO; D::Batch::DIMENSION];
    let mut batch = vec![D::Batch::ZERO; D::Sharing::DIMENSION];
    batch[0] = D::Batch::gen(rng);
    D::convert(&mut share[..], &mut batch[..]);
    share[0].get(0)
}

pub fn random_scalars<D: Domain, R: RngCore>(rng: &mut R, length: usize) -> Vec<D::Scalar> {
    let mut input = Vec::with_capacity(length);
    for _ in 0..length {
        input.push(random_scalar::<D, _>(rng))
    }
    input
}

// Evaluates a program (in the clear)
pub fn evaluate_program<D: Domain>(
    program: &[Instruction<D::Scalar>],
    inputs: &[D::Scalar],
    branch: &[D::Scalar],
    challenge: Option<(usize, D::Scalar)>,
) -> (Vec<usize>, Vec<D::Scalar>) {
    let mut wires = VecMap::new();
    let mut output = Vec::new();
    let mut output_wires = Vec::new();
    let mut inputs = inputs.iter().cloned();
    let mut branch = branch.iter().cloned();

    for step in program {
        match *step {
            Instruction::NrOfWires(_nr) => {}
            Instruction::Input(dst) => {
                wires.set(dst, inputs.next().unwrap());
            }
            Instruction::Branch(dst) => {
                wires.set(dst, branch.next().unwrap());
            }
            Instruction::LocalOp(dst, src) => {
                wires.set(dst, wires.get(src).operation());
            }
            Instruction::Add(dst, src1, src2) => {
                wires.set(dst, wires.get(src1) + wires.get(src2));
            }
            Instruction::Mul(dst, src1, src2) => {
                wires.set(dst, wires.get(src1) * wires.get(src2));
            }
            Instruction::Const(dst, c) => {
                if let Some(cha) = challenge {
                    if cha.0 == dst {
                        wires.set(dst, cha.1);
                    } else {
                        wires.set(dst, c);
                    }
                } else {
                    wires.set(dst, c);
                }
            }
            Instruction::AddConst(dst, src, c) => {
                wires.set(dst, wires.get(src) + c);
            }
            Instruction::MulConst(dst, src, c) => {
                wires.set(dst, wires.get(src) * c);
            }
            Instruction::Output(src) => {
                output.push(wires.get(src));
                output_wires.push(src);
            }
        }
    }

    (output_wires, output)
}

// Evaluates two programs with fieldswitching (in the clear)
pub fn evaluate_fieldswitching_btoa_program<D: Domain, D2: Domain>(
    conn_program: &[ConnectionInstruction],
    program1: &[Instruction<D::Scalar>],
    program2: &[Instruction<D2::Scalar>],
    inputs: &[D::Scalar],
    branch1: &[D::Scalar],
    branch2: &[D2::Scalar],
) -> Vec<D2::Scalar> {
    let (out_wires, output1) = evaluate_program::<D>(program1, inputs, branch1, None);

    let mut wires1 = Vec::new();

    for step in conn_program {
        match *step {
            ConnectionInstruction::BToA(_dst, src) => {
                let mut input = D2::Scalar::ZERO;
                let mut pow_two = D2::Scalar::ONE;
                let two = D2::Scalar::ONE + D2::Scalar::ONE;
                for (i, _src) in src.iter().cloned().enumerate() {
                    if i >= D2::NR_OF_BITS {
                        break;
                    }
                    let index = out_wires.iter().position(|&x| x == _src).unwrap();
                    input = input + convert_bit::<D, D2>(output1[index]) * pow_two;
                    pow_two = two * pow_two;
                }
                // wires1.set(dst, input);
                wires1.push(input);
            }
            ConnectionInstruction::AToB(_dst, _src) => {}
            ConnectionInstruction::Challenge(_dst) => {}
        }
    }

    let (_wires, output2) = evaluate_program::<D2>(program2, &wires1[..], branch2, None);

    output2
}

fn convert_bit<D: Domain, D2: Domain>(input: D::Scalar) -> D2::Scalar {
    if input == D::Scalar::ONE {
        return D2::Scalar::ONE;
    } else {
        return D2::Scalar::ZERO;
    }
}

// Generates a random program for property based test
pub fn random_program<D: Domain, R: RngCore>(
    rng: &mut R,
    length: usize,
    memory: usize,
) -> (usize, usize, Vec<Instruction<D::Scalar>>) {
    let mut program: Vec<Instruction<D::Scalar>> = Vec::new();
    let mut assigned: Vec<usize> = vec![0];
    let mut num_inputs: usize = 1;
    let mut num_branch: usize = 0;

    program.push(Instruction::Input(0));

    let mut largest = 1;
    while program.len() < length {
        // random source and destination indexes
        let dst: usize = rng.gen::<usize>() % memory;
        let src1: usize = assigned[rng.gen::<usize>() % assigned.len()];
        let src2: usize = assigned[rng.gen::<usize>() % assigned.len()];
        if largest < dst {
            largest = dst;
        }
        if largest < src1 {
            largest = src1;
        }
        if largest < src2 {
            largest = src2;
        }

        // pick random instruction
        match rng.gen::<usize>() % 8 {
            0 => {
                program.push(Instruction::Input(dst));
                assigned.push(dst);
                num_inputs += 1;
            }
            1 => {
                program.push(Instruction::Branch(dst));
                assigned.push(dst);
                num_branch += 1;
            }
            2 => {
                program.push(Instruction::Add(dst, src1, src2));
                assigned.push(dst);
            }
            3 => {
                program.push(Instruction::Mul(dst, src1, src2));
                assigned.push(dst);
            }
            4 => {
                program.push(Instruction::AddConst(dst, src1, random_scalar::<D, _>(rng)));
                assigned.push(dst);
            }
            5 => {
                program.push(Instruction::MulConst(dst, src1, random_scalar::<D, _>(rng)));
                assigned.push(dst);
            }
            6 => {
                program.push(Instruction::Output(src1));
            }
            7 => program.push(Instruction::LocalOp(dst, src1)),
            _ => unreachable!(),
        }
    }
    program.insert(0, Instruction::NrOfWires(largest));

    (num_inputs, num_branch, program)
}

#[test]
pub fn test_evaluate_program() {
    let mut rng = thread_rng();

    let program1 = mini_program::<Gf2P8>();
    let program2 = mini_program::<Gf2P8>();
    let conn_program = connection_program();
    let input = random_scalars::<Gf2P8, _>(&mut rng, 4);

    let branch: Vec<BitScalar> = vec![];
    let branches: Vec<Vec<BitScalar>> = vec![branch];

    let output = evaluate_fieldswitching_btoa_program::<Gf2P8, Gf2P8>(
        &conn_program[..],
        &program1[..],
        &program2[..],
        &input[..],
        &branches[0][..],
        &branches[0][..],
    );
    assert_eq!(output, input);
}

pub fn mini_program<D: Domain>() -> Vec<Instruction<D::Scalar>> {
    let mut program: Vec<Instruction<D::Scalar>> = Vec::new();
    program.push(Instruction::NrOfWires(8));
    program.push(Instruction::Input(0));
    program.push(Instruction::Input(1));
    program.push(Instruction::Input(2));
    program.push(Instruction::Input(3));

    program.push(Instruction::AddConst(4, 0, D::Scalar::ONE));
    program.push(Instruction::AddConst(5, 1, D::Scalar::ONE));
    program.push(Instruction::AddConst(6, 2, D::Scalar::ONE));
    program.push(Instruction::AddConst(7, 3, D::Scalar::ONE));

    program.push(Instruction::Output(4));
    program.push(Instruction::Output(5));
    program.push(Instruction::Output(6));
    program.push(Instruction::Output(7));

    program
}

pub fn connection_program() -> Vec<ConnectionInstruction> {
    let mut program: Vec<ConnectionInstruction> = Vec::new();

    let src1: [usize; 64] = [4; 64];
    let src4: [usize; 64] = [7; 64];
    let src2: [usize; 64] = [5; 64];
    let src3: [usize; 64] = [6; 64];
    program.push(ConnectionInstruction::BToA(0, src1));
    program.push(ConnectionInstruction::BToA(1, src2));
    program.push(ConnectionInstruction::BToA(2, src3));
    program.push(ConnectionInstruction::BToA(3, src4));

    program
}

#[test]
pub fn test_evaluate_program_64() {
    let mut rng = thread_rng();

    let program1 = mini_bool_program_64();
    let program2 = mini_arith_program_64();
    let conn_program = connection_program_64();
    let input = random_scalars::<Gf2P8, _>(&mut rng, 64);

    let branch1: Vec<BitScalar> = vec![];
    let branches1: Vec<Vec<BitScalar>> = vec![branch1];
    let branch2: Vec<Scalar> = vec![];
    let branches2: Vec<Vec<Scalar>> = vec![branch2];

    let output = evaluate_fieldswitching_btoa_program::<Gf2P8, Z64P8>(
        &conn_program[..],
        &program1[..],
        &program2[..],
        &input[..],
        &branches1[0][..],
        &branches2[0][..],
    );
    assert_eq!(output[0], output[1]);
}

pub fn mini_bool_program_64() -> Vec<Instruction<BitScalar>> {
    let mut program: Vec<Instruction<BitScalar>> = Vec::new();
    program.push(Instruction::NrOfWires(128));
    for i in 0..64 {
        program.push(Instruction::Input(i));
        program.push(Instruction::AddConst(i + 64, i, BitScalar::ONE));
        program.push(Instruction::Output(i + 64));
    }

    program
}

pub fn connection_program_64() -> Vec<ConnectionInstruction> {
    let mut program: Vec<ConnectionInstruction> = Vec::new();

    let mut src: [usize; 64] = [0; 64];
    for i in 64..128 {
        src[i - 64] = i;
    }

    program.push(ConnectionInstruction::BToA(0, src));

    program
}

pub fn mini_arith_program_64() -> Vec<Instruction<Scalar>> {
    let mut program: Vec<Instruction<Scalar>> = Vec::new();
    program.push(Instruction::NrOfWires(3));
    program.push(Instruction::Input(0));

    let two = Scalar::ONE + Scalar::ONE;
    program.push(Instruction::MulConst(1, 0, two));
    program.push(Instruction::Add(2, 0, 0));

    program.push(Instruction::Output(1));
    program.push(Instruction::Output(2));

    program
}
