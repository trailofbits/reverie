use crate::{gf2, z64, Domain};
use crate::{CombineOperation, Operation};

use rand::Rng;
use std::cmp::max;

use std::ops::Index;

pub struct VecMap<T>(pub(crate) Vec<T>);

impl<T: Default + Clone> From<Vec<T>> for VecMap<T> {
    fn from(vec: Vec<T>) -> VecMap<T> {
        VecMap(vec)
    }
}

impl<T: Default + Clone> Index<usize> for VecMap<T> {
    type Output = T;

    fn index(&self, idx: usize) -> &Self::Output {
        &self.0[idx]
    }
}

impl<T> AsRef<[T]> for VecMap<T> {
    fn as_ref(&self) -> &[T] {
        &self.0[..]
    }
}

impl<T: Default + Clone> VecMap<T> {
    pub fn new(wires: usize) -> Self {
        VecMap(vec![T::default(); wires])
    }

    #[inline(always)]
    pub fn set(&mut self, idx: usize, val: T) {
        self.0[idx] = val;
    }

    #[inline(always)]
    pub fn get(&self, idx: usize) -> &T {
        &self.0[idx]
    }
}

fn _gf2_to_z64(b: gf2::Recon) -> <z64::Domain as Domain>::ConstType {
    let as_bool = b.pack > 0;
    if as_bool {
        z64::Domain::ONE
    } else {
        z64::Domain::ZERO
    }
}

// Evaluates a composite program (in the clear)
pub fn evaluate_composite_program(program: &[CombineOperation], bool_inputs: &[gf2::Recon]) {
    let (bool_wire_count, arith_wire_count) = largest_wires(program);

    let mut bool_wires = VecMap::<gf2::Recon>::new(bool_wire_count);
    let mut bool_inputs = bool_inputs.iter().cloned();

    let mut arith_wires = VecMap::<z64::Recon>::new(arith_wire_count);

    for step in program {
        match *step {
            CombineOperation::GF2(gf2_insn) => match gf2_insn {
                Operation::Input(dst) => {
                    bool_wires.set(dst, bool_inputs.next().unwrap());
                }
                Operation::Random(dst) => {
                    let val: bool = rand::thread_rng().gen();
                    bool_wires.set(dst, gf2::Recon::from(val));
                }
                Operation::Add(dst, src1, src2) => {
                    bool_wires.set(dst, *bool_wires.get(src1) + *bool_wires.get(src2));
                }
                Operation::Sub(dst, src1, src2) => {
                    bool_wires.set(dst, *bool_wires.get(src1) - *bool_wires.get(src2));
                }
                Operation::Mul(dst, src1, src2) => {
                    bool_wires.set(dst, *bool_wires.get(src1) * *bool_wires.get(src2));
                }
                Operation::AddConst(dst, src, c) => {
                    bool_wires.set(dst, *bool_wires.get(src) + c.into());
                }
                Operation::MulConst(dst, src, c) => {
                    bool_wires.set(dst, *bool_wires.get(src) * c.into());
                }
                Operation::AssertZero(src) => {
                    assert_eq!(*bool_wires.get(src), gf2::Domain::ZERO.into());
                }
            },
            CombineOperation::Z64(z64_insn) => {
                match z64_insn {
                    Operation::Random(dst) => {
                        let val: u64 = rand::thread_rng().gen();
                        arith_wires.set(dst, z64::Recon::from(val));
                    }
                    Operation::Add(dst, src1, src2) => {
                        arith_wires.set(dst, *arith_wires.get(src1) + *arith_wires.get(src2));
                    }
                    Operation::Sub(dst, src1, src2) => {
                        arith_wires.set(dst, *arith_wires.get(src1) - *arith_wires.get(src2));
                    }
                    Operation::Mul(dst, src1, src2) => {
                        arith_wires.set(dst, *arith_wires.get(src1) * *arith_wires.get(src2));
                    }
                    Operation::AddConst(dst, src, c) => {
                        arith_wires.set(dst, *arith_wires.get(src) + c.into());
                    }
                    Operation::MulConst(dst, src, c) => {
                        arith_wires.set(dst, *arith_wires.get(src) * c.into());
                    }
                    Operation::AssertZero(src) => {
                        let val = *arith_wires.get(src);
                        // assert_eq!(val, z64::Domain::ZERO);
                        println!(
                            "{} => {} ({:?})",
                            src,
                            if val == z64::Domain::ZERO.into() {
                                "OKAY"
                            } else {
                                "FAIL"
                            },
                            val
                        );
                    }
                    _ => {
                        unimplemented!("Can't evaluate {:?} in Z64", z64_insn)
                    }
                }
            }
            CombineOperation::B2A(dst, low) => {
                let mut running_val = z64::Domain::ZERO;
                let mut power = z64::Domain::ONE;
                for bit in (low..(low + 64)).rev() {
                    running_val += _gf2_to_z64(*bool_wires.get(bit)) * power;
                    power *= z64::Domain::ONE + z64::Domain::ONE;
                }
                arith_wires.set(dst, running_val.into());
            }
            CombineOperation::SizeHint(_z64, _gf2) => (),
        }
    }
}

pub fn largest_wires_exhaustive(program: &[CombineOperation]) -> (usize, usize) {
    let mut bool_count: usize = 0;
    let mut arith_count: usize = 0;

    for step in program {
        match *step {
            CombineOperation::GF2(gf2_insn) => match gf2_insn {
                Operation::Input(dst) => {
                    bool_count = max(bool_count, dst);
                }
                Operation::Random(dst) => {
                    bool_count = max(bool_count, dst);
                }
                Operation::Add(dst, src1, src2) => {
                    bool_count = max(bool_count, max(dst, max(src1, src2)));
                }
                Operation::Sub(dst, src1, src2) => {
                    bool_count = max(bool_count, max(dst, max(src1, src2)));
                }
                Operation::Mul(dst, src1, src2) => {
                    bool_count = max(bool_count, max(dst, max(src1, src2)));
                }
                Operation::AddConst(dst, src, _c) => {
                    bool_count = max(bool_count, max(dst, src));
                }
                Operation::MulConst(dst, src, _c) => {
                    bool_count = max(bool_count, max(dst, src));
                }
                Operation::AssertZero(src) => {
                    bool_count = max(bool_count, src);
                }
            },
            CombineOperation::Z64(z64_insn) => match z64_insn {
                Operation::Random(dst) => {
                    arith_count = max(arith_count, dst);
                }
                Operation::Add(dst, src1, src2) => {
                    arith_count = max(arith_count, max(dst, max(src1, src2)));
                }
                Operation::Sub(dst, src1, src2) => {
                    arith_count = max(arith_count, max(dst, max(src1, src2)));
                }
                Operation::Mul(dst, src1, src2) => {
                    arith_count = max(arith_count, max(dst, max(src1, src2)));
                }
                Operation::AddConst(dst, src, _c) => {
                    arith_count = max(arith_count, max(dst, src));
                }
                Operation::MulConst(dst, src, _c) => {
                    arith_count = max(arith_count, max(dst, src));
                }
                Operation::AssertZero(src) => {
                    arith_count = max(arith_count, src);
                }
                _ => {
                    unimplemented!("Can't evaluate {:?} in Z64", z64_insn)
                }
            },
            CombineOperation::B2A(z64, gf2_base) => {
                arith_count = max(arith_count, z64);
                bool_count = max(bool_count, gf2_base + 63);
            }
            CombineOperation::SizeHint(z64, gf2) => {
                arith_count = max(arith_count, z64);
                bool_count = max(bool_count, gf2);
            }
        }
    }
    (bool_count + 1, arith_count + 1)
}

pub fn largest_wires(program: &[CombineOperation]) -> (usize, usize) {
    if let CombineOperation::SizeHint(z64_cells, gf2_cells) = program[0] {
        (gf2_cells, z64_cells)
    } else {
        largest_wires_exhaustive(program)
    }
}
