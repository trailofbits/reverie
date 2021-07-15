use num_traits::Zero;

use crate::algebra::Domain;
use crate::interpreter::Wire;
use crate::transcript::Transcript;
use crate::Operation;

pub struct Instance<D: Domain, T: Transcript<D>> {
    pub(crate) transcript: T,       //
    pub(crate) wires: Vec<Wire<D>>, // masks and corrections for wires (masked values)
}

impl<D: Domain, T: Transcript<D>> Instance<D, T> {
    pub fn new(transcript: T, cells: usize) -> Self {
        Instance {
            wires: vec![Default::default(); cells],
            transcript,
        }
    }

    pub fn extract(self) -> T {
        self.transcript
    }

    pub(crate) fn op_mul(transcript: &mut T, w1: &Wire<D>, w2: &Wire<D>) -> Wire<D> {
        let mask_ab = transcript.new_mask();
        let mask_new = transcript.new_mask();

        #[cfg(debug_assertions)]
        {
            println!("tx: mask_ab             = {:?}", &mask_ab);
            println!("tx: mask_new            = {:?}", &mask_new);
        }

        // preprocessing
        let a = D::reconstruct(&w1.mask);
        let b = D::reconstruct(&w2.mask);
        let c = D::reconstruct(&mask_ab);

        // compute multiplication correction
        let delta = transcript.correction(a * b - c);

        // broadcast s
        let s: D::Share = w2.mask * w1.corr + w1.mask * w2.corr + mask_ab - mask_new;
        let recon = transcript.reconstruct(s) + delta;

        #[cfg(debug_assertions)]
        {
            println!("tx: delta               = {:?}", &delta);
            println!("tx: w1                  = {:?}", &w1);
            println!("tx: w2                  = {:?}", &w2);
            println!("tx: w2.mask * w1.corr   = {:?}", w2.mask * w1.corr);
            println!("tx: w1.mask * w2.corr   = {:?}", w1.mask * w2.corr);
        }

        // corrected wire
        let result = Wire {
            mask: mask_new,
            corr: recon + w1.corr * w2.corr,
        };

        // check that multiplied correctly when proving in debug mode
        #[cfg(debug_assertions)]
        if T::IS_PROVER {
            debug_assert_eq!(result.value(), w1.value() * w2.value());
        }

        result
    }

    pub(crate) fn op_add(w1: &Wire<D>, w2: &Wire<D>) -> Wire<D> {
        Wire {
            mask: w1.mask + w2.mask,
            corr: w1.corr + w2.corr,
        }
    }

    pub(crate) fn op_sub(w1: &Wire<D>, w2: &Wire<D>) -> Wire<D> {
        Wire {
            mask: w1.mask - w2.mask,
            corr: w1.corr - w2.corr,
        }
    }

    pub(crate) fn op_add_const(w: &Wire<D>, v: D::Recon) -> Wire<D> {
        Wire {
            mask: w.mask,
            corr: w.corr + v,
        }
    }

    pub(crate) fn op_sub_const(w: &Wire<D>, v: D::Recon) -> Wire<D> {
        Wire {
            mask: w.mask,
            corr: w.corr - v,
        }
    }

    pub(crate) fn op_mul_const(w: &Wire<D>, v: D::Recon) -> Wire<D> {
        Wire {
            mask: w.mask * v,
            corr: w.corr * v,
        }
    }

    pub fn step(&mut self, op: &Operation<D::ConstType>) {
        match op {
            Operation::Input(dst) => {
                self.wires[*dst] = self.transcript.input();
            }

            Operation::Add(dst, src1, src2) => {
                self.wires[*dst] = Self::op_add(&self.wires[*src1], &self.wires[*src2])
            }

            Operation::Sub(dst, src1, src2) => {
                self.wires[*dst] = Self::op_sub(&self.wires[*src1], &self.wires[*src2])
            }

            Operation::Mul(dst, src1, src2) => {
                self.wires[*dst] =
                    Self::op_mul(&mut self.transcript, &self.wires[*src1], &self.wires[*src2]);
            }

            Operation::AddConst(dst, src, val) => {
                self.wires[*dst] = Self::op_add_const(&self.wires[*src], (*val).into())
            }

            Operation::SubConst(dst, src, val) => {
                self.wires[*dst] = Self::op_sub_const(&self.wires[*src], (*val).into())
            }

            Operation::MulConst(dst, src, val) => {
                self.wires[*dst] = Self::op_mul_const(&self.wires[*src], (*val).into())
            }

            Operation::AssertZero(src) => {
                let w = &self.wires[*src];
                let m = self.transcript.reconstruct(w.mask);
                self.transcript.zero_check(w.corr + m);
            }

            Operation::Random(dst) => {
                self.wires[*dst] = Wire {
                    mask: self.transcript.new_mask(),
                    corr: Zero::zero(),
                };
            }

            Operation::Const(dst, val) => {
                self.wires[*dst] = Wire {
                    mask: Zero::zero(),
                    corr: (*val).into(),
                }
            }
        };
    }

    #[cfg(test)]
    pub fn get_wire(&self, idx: usize) -> D::Recon {
        self.wires[idx].value()
    }
}

#[cfg(test)]
mod test {
    use std::iter::Map;
    use std::slice::Iter;

    use crate::crypto::prg::KEY_SIZE;
    use crate::transcript::ProverTranscript;
    use crate::{gf2, z64, PACKED};

    use super::*;

    fn test_gate_gf2(witness: &[bool], gate: Operation<bool>) -> gf2::Recon {
        let mut program: Vec<Operation<bool>> = Vec::new();

        let dest = gate.dst();
        for (idx, _) in witness.iter().enumerate() {
            program.push(Operation::Input(idx))
        }
        program.push(gate);

        let mut instance: Instance<
            gf2::Domain,
            ProverTranscript<gf2::Domain, Map<Iter<bool>, fn(&bool) -> gf2::Recon>>,
        > = Instance {
            wires: vec![Default::default(); program.len() + 2],
            transcript: ProverTranscript::new(
                witness.iter().map(|x| (*x).into()),
                [[0u8; KEY_SIZE]; PACKED],
            ),
        };

        for op in program.iter() {
            instance.step(op);
        }

        instance.get_wire(dest.expect("This type of gate doesn't write anywhere"))
    }

    fn test_gate_z64(witness: &[u64], gate: Operation<u64>) -> z64::Recon {
        let mut program: Vec<Operation<u64>> = Vec::new();

        let dest = gate.dst();
        for (idx, _) in witness.iter().enumerate() {
            program.push(Operation::Input(idx))
        }
        program.push(gate);

        let mut instance: Instance<
            z64::Domain,
            ProverTranscript<z64::Domain, Map<Iter<u64>, fn(&u64) -> z64::Recon>>,
        > = Instance {
            wires: vec![Default::default(); program.len() + 2],
            transcript: ProverTranscript::new(
                witness.iter().map(|x| (*x).into()),
                [[0u8; KEY_SIZE]; PACKED],
            ),
        };

        for op in program.iter() {
            instance.step(op);
        }

        instance.get_wire(dest.unwrap_or(0))
    }

    #[test]
    fn test_mul_gf2() {
        let gate = Operation::Mul(2, 1, 0);

        // 1 * 1
        let actual = test_gate_gf2(&[true, true], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ONE.into();

        assert_eq!(expected, actual);

        // 1 * 0
        let actual = test_gate_gf2(&[true, false], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ZERO.into();

        assert_eq!(expected, actual);

        // 0 * 0
        let actual = test_gate_gf2(&[false, false], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ZERO.into();

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_mulc_gf2() {
        let gate = Operation::MulConst(1, 0, gf2::Domain::ONE.into());

        // 1 * 1
        let actual = test_gate_gf2(&[true], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ONE.into();

        assert_eq!(expected, actual);

        // 0 * 1
        let actual = test_gate_gf2(&[false], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ZERO.into();

        assert_eq!(expected, actual);

        let gate = Operation::MulConst(1, 0, gf2::Domain::ZERO.into());

        // 1 * 0
        let actual = test_gate_gf2(&[true], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ZERO.into();

        assert_eq!(expected, actual);

        // 0 * 0
        let actual = test_gate_gf2(&[false], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ZERO.into();

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_add_gf2() {
        let gate = Operation::Add(2, 1, 0);

        // 1 + 1
        let actual = test_gate_gf2(&[true, true], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ZERO.into();

        assert_eq!(expected, actual);

        // 1 + 0
        let actual = test_gate_gf2(&[true, false], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ONE.into();

        assert_eq!(expected, actual);

        // 0 + 0
        let actual = test_gate_gf2(&[false, false], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ZERO.into();

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_addc_gf2() {
        let gate = Operation::AddConst(1, 0, gf2::Domain::ONE.into());

        // 1 + 1
        let actual = test_gate_gf2(&[true], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ZERO.into();

        assert_eq!(expected, actual);

        // 0 + 1
        let actual = test_gate_gf2(&[false], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ONE.into();

        assert_eq!(expected, actual);

        let gate = Operation::AddConst(1, 0, gf2::Domain::ZERO.into());

        // 1 + 0
        let actual = test_gate_gf2(&[true], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ONE.into();

        assert_eq!(expected, actual);

        // 0 + 0
        let actual = test_gate_gf2(&[false], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ZERO.into();

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_sub_gf2() {
        let gate = Operation::Sub(2, 1, 0);

        // 1 - 1
        let actual = test_gate_gf2(&[true, true], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ZERO.into();

        assert_eq!(expected, actual);

        // 1 - 0
        let actual = test_gate_gf2(&[true, false], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ONE.into();

        assert_eq!(expected, actual);

        // 0 - 0
        let actual = test_gate_gf2(&[false, false], gate.clone());
        let expected: gf2::Recon = gf2::Domain::ZERO.into();

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_add_z64() {
        let gate = Operation::Add(2, 1, 0);

        // 0 + 0
        let inputs = [0, 0];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0] + inputs[1]).into();
        assert_eq!(expected, actual);

        // 0 + 1
        let inputs = [0, 1];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0] + inputs[1]).into();
        assert_eq!(expected, actual);

        // 400 + 20
        let inputs = [400, 20];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0] + inputs[1]).into();
        assert_eq!(expected, actual);

        // almost wrapping
        let inputs = [u64::MAX - 20, 20];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0].wrapping_add(inputs[1])).into();
        assert_eq!(expected, actual);

        // wrapping
        let inputs = [u64::MAX - 1, 20];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0].wrapping_add(inputs[1])).into();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_addc_z64() {
        // 0 + 0
        let inputs = [0];
        let actual = test_gate_z64(&inputs, Operation::AddConst(1, 0, 0));
        let expected: z64::Recon = 0.into();
        assert_eq!(expected, actual);

        // 0 + 1
        let inputs = [0];
        let actual = test_gate_z64(&inputs, Operation::AddConst(1, 0, 1));
        let expected: z64::Recon = 1.into();
        assert_eq!(expected, actual);

        let gate = Operation::AddConst(1, 0, 20);
        // 400 + 20
        let inputs = [400];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = 420.into();
        assert_eq!(expected, actual);

        // almost wrapping
        let inputs = [u64::MAX - 20];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0].wrapping_add(20)).into();
        assert_eq!(expected, actual);

        // wrapping
        let inputs = [u64::MAX - 1];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0].wrapping_add(20)).into();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_mul_z64() {
        let gate = Operation::Mul(2, 1, 0);

        // 0 * 0
        let inputs = [0, 0];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0] * inputs[1]).into();
        assert_eq!(expected, actual);

        // 0 * 1
        let inputs = [0, 1];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0] * inputs[1]).into();
        assert_eq!(expected, actual);

        // 400 * 20
        let inputs = [400, 20];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0] * inputs[1]).into();
        assert_eq!(expected, actual);

        // almost wrapping
        let inputs = [u64::MAX - 20, 20];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0].wrapping_mul(inputs[1])).into();
        assert_eq!(expected, actual);

        // wrapping
        let inputs = [u64::MAX - 1, 20];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0].wrapping_mul(inputs[1])).into();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_mulc_z64() {
        // 0 * 0
        let inputs = [0];
        let actual = test_gate_z64(&inputs, Operation::MulConst(1, 0, 0));
        let expected: z64::Recon = 0.into();
        assert_eq!(expected, actual);

        // 0 * 1
        let inputs = [0];
        let actual = test_gate_z64(&inputs, Operation::MulConst(1, 0, 1));
        let expected: z64::Recon = 0.into();
        assert_eq!(expected, actual);

        let gate = Operation::MulConst(1, 0, 20);
        // 400 * 20
        let inputs = [400];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = 8000.into();
        assert_eq!(expected, actual);

        // almost wrapping
        let inputs = [u64::MAX - 20];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0].wrapping_mul(20)).into();
        assert_eq!(expected, actual);

        // wrapping
        let inputs = [u64::MAX - 1];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0].wrapping_mul(20)).into();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_sub_z64() {
        let gate = Operation::Sub(2, 0, 1);

        // 0 - 0
        let inputs = [0, 0];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0] - inputs[1]).into();
        assert_eq!(expected, actual);

        // 1 - 0
        let inputs = [1, 0];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0] - inputs[1]).into();
        assert_eq!(expected, actual);

        // 400 - 20
        let inputs = [400, 20];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0] - inputs[1]).into();
        assert_eq!(expected, actual);

        // almost wrapping
        let inputs = [20, 20];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0].wrapping_sub(inputs[1])).into();
        assert_eq!(expected, actual);

        // wrapping
        let inputs = [10, 20];
        let actual = test_gate_z64(&inputs, gate.clone());
        let expected: z64::Recon = (inputs[0].wrapping_sub(inputs[1])).into();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_assert0_z64() {
        let inputs = [0];
        test_gate_z64(&inputs, Operation::AssertZero(0));
    }
}
