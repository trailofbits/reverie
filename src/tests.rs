use rand::RngCore;
use rand::{thread_rng, Rng};

use crate::algebra::gf2::{BitScalar, Gf2P8};
use crate::algebra::z64::{Scalar, Z64P8};
use crate::algebra::*;
use crate::util::eval;
use crate::{ConnectionInstruction, Instruction};

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

    let output = eval::evaluate_fieldswitching_btoa_program::<Gf2P8, Gf2P8>(
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

    let output = eval::evaluate_fieldswitching_btoa_program::<Gf2P8, Z64P8>(
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

pub fn mini_random_program_64<R: RngCore>(rng: &mut R) -> Vec<Instruction<BitScalar>> {
    let mut program: Vec<Instruction<BitScalar>> = Vec::new();
    let mut assigned: Vec<usize> = vec![];

    let memory = 128;

    program.push(Instruction::NrOfWires(memory));
    for i in 0..64 {
        program.push(Instruction::Input(i));
        assigned.push(i);
    }

    while assigned.len() < memory{
        let dst: usize = (rng.gen::<usize>() % 64) + 64;
        let src1: usize = assigned[rng.gen::<usize>() % assigned.len()];
        let src2: usize = assigned[rng.gen::<usize>() % assigned.len()];

        match rng.gen::<usize>() % 5 {
            0 => {
                program.push(Instruction::Add(dst, src1, src2));
                assigned.push(dst);
            }
            1 => {
                program.push(Instruction::Mul(dst, src1, src2));
                assigned.push(dst);
            }
            2 => {
                program.push(Instruction::AddConst(dst, src1, random_scalar::<Gf2P8, _>(rng)));
                assigned.push(dst);
            }
            3 => {
                program.push(Instruction::MulConst(dst, src1, random_scalar::<Gf2P8, _>(rng)));
                assigned.push(dst);
            }
            4 => {
                program.push(Instruction::Sub(dst, src1, src2));
                assigned.push(dst);
            }
            _ => unreachable!(),
        }
    }

    for i in 0..64 {
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
