use crate::algebra::{Domain, LocalOperation, RingElement};
use crate::util::VecMap;
use crate::{ConnectionInstruction, Instruction};

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
    fn convert_bit<D: Domain, D2: Domain>(input: D::Scalar) -> D2::Scalar {
        if input == D::Scalar::ONE {
            return D2::Scalar::ONE;
        } else {
            return D2::Scalar::ZERO;
        }
    }

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
