use rand::{Rng, thread_rng};
use rand::RngCore;

use crate::algebra::*;
use crate::util::{VecMap, random_scalar};
use crate::{util, Instruction, InstructionCombine};
use crate::algebra::gf2::BitScalar;
use crate::algebra::z64::Scalar;

pub fn random_scalars<D: Domain, R: RngCore>(rng: &mut R, length: usize) -> Vec<D::Scalar> {
    let mut input = Vec::with_capacity(length);
    for _ in 0..length {
        input.push(util::random_scalar::<D, _>(rng))
    }
    input
}

// Evaluates a program (in the clear)
pub fn evaluate_program<D: Domain>(
    program: &[Instruction<D::Scalar>],
    inputs: &[D::Scalar],
) -> Vec<D::Scalar> {
    let mut wires = VecMap::new();
    let mut output = Vec::new();
    let mut inputs = inputs.iter().cloned();

    for step in program {
        match *step {
            Instruction::Input(dst) => {
                wires.set(dst, inputs.next().unwrap());
            }
            Instruction::LocalOp(dst, src) => {
                wires.set(dst, wires.get(src).operation());
            }
            Instruction::Add(dst, src1, src2) => {
                wires.set(dst, wires.get(src1) + wires.get(src2));
            }
            Instruction::Sub(dst, src1, src2) => {
                wires.set(dst, wires.get(src1) - wires.get(src2));
            }
            Instruction::Mul(dst, src1, src2) => {
                wires.set(dst, wires.get(src1) * wires.get(src2));
            }
            Instruction::Const(dst, c) => {
                wires.set(dst, c);
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
            Instruction::Random(dst) => {
                wires.set(dst, random_scalar::<D, _>(&mut thread_rng()));
            }
        }
    }

    output
}

// Generates a random program for property based test
pub fn random_program<D: Domain, R: RngCore>(
    rng: &mut R,
    length: usize,
    memory: usize,
) -> (usize, Vec<Instruction<D::Scalar>>) {
    let mut program: Vec<Instruction<D::Scalar>> = Vec::new();
    let mut assigned: Vec<usize> = vec![0];
    let mut num_inputs: usize = 1;

    program.push(Instruction::Input(0));

    while program.len() < length {
        // random source and destination indexes
        let dst: usize = rng.gen::<usize>() % memory;
        let src1: usize = assigned[rng.gen::<usize>() % assigned.len()];
        let src2: usize = assigned[rng.gen::<usize>() % assigned.len()];

        // pick random instruction
        match rng.gen::<usize>() % 7 {
            0 => {
                program.push(Instruction::Input(dst));
                assigned.push(dst);
                num_inputs += 1;
            }
            1 => {
                program.push(Instruction::Add(dst, src1, src2));
                assigned.push(dst);
            }
            2 => {
                program.push(Instruction::Mul(dst, src1, src2));
                assigned.push(dst);
            }
            3 => {
                program.push(Instruction::AddConst(
                    dst,
                    src1,
                    util::random_scalar::<D, _>(rng),
                ));
                assigned.push(dst);
            }
            4 => {
                program.push(Instruction::MulConst(
                    dst,
                    src1,
                    util::random_scalar::<D, _>(rng),
                ));
                assigned.push(dst);
            }
            5 => {
                program.push(Instruction::Output(src1));
            }
            6 => program.push(Instruction::LocalOp(dst, src1)),
            _ => unreachable!(),
        }
    }

    (num_inputs, program)
}

fn _gf2_to_z64(b: BitScalar) -> Scalar {
    match b{
        BitScalar::ZERO => Scalar::ZERO,
        BitScalar::ONE => Scalar::ONE,
        _ => {unimplemented!("Where did you get a bitscalar that wasn't a zero or a one?")}
    }
}


// Evaluates a composite program (in the clear)
pub fn evaluate_composite_program(
    program: &[InstructionCombine],
    bool_inputs: &[BitScalar],
) -> Vec<Scalar> {
    let mut bool_wires = VecMap::<BitScalar>::new();
    let mut bool_output = Vec::new();
    let mut bool_inputs = bool_inputs.iter().cloned();

    let mut arith_wires = VecMap::<Scalar>::new();
    let mut arith_output = Vec::new();
    let mut arith_inputs = VecMap::<Scalar>::new();
    let mut last_arith_input = 0;

    for step in program {
        match *step {
            InstructionCombine::OpGF2(gf2_insn) => {
                match gf2_insn {
                    Instruction::Input(dst) => {
                        bool_wires.set(dst, bool_inputs.next().unwrap());
                    }
                    Instruction::LocalOp(dst, src) => {
                        bool_wires.set(dst, bool_wires.get(src).operation());
                    }
                    Instruction::Add(dst, src1, src2) => {
                        bool_wires.set(dst, bool_wires.get(src1) + bool_wires.get(src2));
                    }
                    Instruction::Sub(dst, src1, src2) => {
                        bool_wires.set(dst, bool_wires.get(src1) - bool_wires.get(src2));
                    }
                    Instruction::Mul(dst, src1, src2) => {
                        bool_wires.set(dst, bool_wires.get(src1) * bool_wires.get(src2));
                    }
                    Instruction::Const(dst, c) => {
                        bool_wires.set(dst, c);
                    }
                    Instruction::AddConst(dst, src, c) => {
                        bool_wires.set(dst, bool_wires.get(src) + c);
                    }
                    Instruction::MulConst(dst, src, c) => {
                        bool_wires.set(dst, bool_wires.get(src) * c);
                    }
                    Instruction::Output(src) => {
                        bool_output.push(bool_wires.get(src));
                    }
                    _ => {unimplemented!("Can't evaluate {:?} in GF2", gf2_insn)}
                }
            }
            InstructionCombine::OpZn(z64_insn) => {
                match z64_insn {
                    Instruction::Input(dst) => {
                        arith_wires.set(dst, arith_inputs.get(last_arith_input));
                        last_arith_input += 1;
                    }
                    Instruction::LocalOp(dst, src) => {
                        arith_wires.set(dst, arith_wires.get(src).operation());
                    }
                    Instruction::Add(dst, src1, src2) => {
                        arith_wires.set(dst, arith_wires.get(src1) + arith_wires.get(src2));
                    }
                    Instruction::Sub(dst, src1, src2) => {
                        arith_wires.set(dst, arith_wires.get(src1) - arith_wires.get(src2));
                    }
                    Instruction::Mul(dst, src1, src2) => {
                        arith_wires.set(dst, arith_wires.get(src1) * arith_wires.get(src2));
                    }
                    Instruction::Const(dst, c) => {
                        arith_wires.set(dst, c);
                    }
                    Instruction::AddConst(dst, src, c) => {
                        arith_wires.set(dst, arith_wires.get(src) + c);
                    }
                    Instruction::MulConst(dst, src, c) => {
                        arith_wires.set(dst, arith_wires.get(src) * c);
                    }
                    Instruction::Output(src) => {
                        arith_output.push(arith_wires.get(src));
                    }
                    _ => {unimplemented!("Can't evaluate {:?} in Z64", z64_insn)}
                }
            }
            InstructionCombine::BToA(dst, (low, high)) => {
                let mut running_val = Scalar::ZERO;
                let mut power = Scalar::ONE;
                for bit in low..high{
                    running_val = running_val + _gf2_to_z64(bool_wires.get(bit)) * power;
                    power = power * (Scalar::ONE + Scalar::ONE);
                }
                arith_inputs.set(dst, running_val);
            }
        }
    }

    arith_output
}