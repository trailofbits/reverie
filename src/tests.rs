use crate::algebra::*;
use crate::util::VecMap;
use crate::Instruction;

use rand::seq::SliceRandom;
use rand::Rng;
use rand::RngCore;

pub fn random_scalar<D: Domain, R: RngCore>(rng: &mut R) -> <D::Sharing as RingModule>::Scalar {
    let mut share = vec![D::Sharing::ZERO; D::Batch::DIMENSION];
    let mut batch = vec![D::Batch::ZERO; D::Sharing::DIMENSION];
    batch[0] = D::Batch::gen(rng);
    D::convert(&mut share[..], &mut batch[..]);
    share[0].get(0)
}

pub fn random_input<D: Domain, R: RngCore>(
    rng: &mut R,
    length: usize,
) -> Vec<<D::Sharing as RingModule>::Scalar> {
    let mut input = Vec::with_capacity(length);
    for _ in 0..length {
        input.push(random_scalar::<D, _>(rng))
    }
    input
}

// Evaluates a program (in the clear)
pub fn evaluate_program<D: Domain>(
    program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
    inputs: &[<D::Sharing as RingModule>::Scalar],
) -> Vec<<D::Sharing as RingModule>::Scalar> {
    let mut wires = VecMap::from(inputs.to_owned());
    let mut output = Vec::new();

    for step in program {
        match *step {
            Instruction::Add(dst, src1, src2) => {
                wires.set(dst, wires.get(src1) + wires.get(src2));
            }
            Instruction::Mul(dst, src1, src2) => {
                wires.set(dst, wires.get(src1) * wires.get(src2));
            }
            Instruction::AddConst(dst, src, c) => {
                wires.set(dst, wires.get(src) + c);
            }
            Instruction::MulConst(dst, src, c) => {
                wires.set(dst, wires.get(src) * c);
            }
            Instruction::Output(src) => {
                output.push(wires.get(src));
            }
        }
    }

    output
}

// Generates a random program for property based test
pub fn random_program<D: Domain, R: RngCore>(
    rng: &mut R,
    inputs: usize,
    length: usize,
    output: bool,
) -> Vec<Instruction<<D::Sharing as RingModule>::Scalar>> {
    let mut program: Vec<Instruction<<D::Sharing as RingModule>::Scalar>> = Vec::new();
    let mut unassigned: Vec<usize> = (inputs..inputs + length).collect();
    let mut assigned: Vec<usize> = (0..inputs).collect();

    // we assign wires in random order
    unassigned.shuffle(rng);
    assert_eq!(unassigned.len(), length);

    while program.len() < length {
        let choice = rng.gen::<usize>() % 5;

        // random source indexes
        let src1: usize = assigned[rng.gen::<usize>() % assigned.len()];
        let src2: usize = assigned[rng.gen::<usize>() % assigned.len()];

        match choice {
            0 => {
                let dst = unassigned.pop().unwrap();
                program.push(Instruction::Add(dst, src1, src2));
                assigned.push(dst);
            }
            1 => {
                let dst = unassigned.pop().unwrap();
                program.push(Instruction::Mul(dst, src1, src2));
                assigned.push(dst);
            }
            2 => {
                let dst = unassigned.pop().unwrap();
                program.push(Instruction::AddConst(dst, src1, random_scalar::<D, _>(rng)));
                assigned.push(dst);
            }
            3 => {
                let dst = unassigned.pop().unwrap();
                program.push(Instruction::MulConst(dst, src1, random_scalar::<D, _>(rng)));
                assigned.push(dst);
            }
            4 => {
                if output {
                    program.push(Instruction::Output(src1));
                }
            }
            _ => unreachable!(),
        }
    }

    program
}
