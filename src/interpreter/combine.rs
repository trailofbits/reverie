use crate::algebra::{gf2, z64, Domain};
use crate::crypto::hash::Hash;
use crate::interpreter::Wire;
use crate::transcript::Transcript;
use crate::HASH;
use crate::{CombineOperation, PACKED};

use super::single::Instance;

use std::convert::TryFrom;

use core::mem::MaybeUninit;
use num_traits::Zero;

pub struct CombineInstance<T1: Transcript<gf2::Domain>, T2: Transcript<z64::Domain>> {
    gf2: Instance<gf2::Domain, T1>,
    z64: Instance<z64::Domain, T2>,
}

fn recon_gf2_to_z64<F: FnMut(&gf2::Share) -> gf2::Recon>(
    mut recon: F,
    bits: &[Wire<gf2::Domain>; z64::BIT_SIZE],
) -> z64::Recon {
    let mut z64_value: [u64; PACKED] = [0; PACKED];
    for wire in bits.iter() {
        let gf2_value: [u8; PACKED] = (recon(&wire.mask) + wire.corr).into();
        for j in 0..PACKED {
            debug_assert!(gf2_value[j] < 2);
            z64_value[j] <<= 1;
            z64_value[j] |= gf2_value[j] as u64;
        }
    }
    for v in z64_value.iter_mut() {
        *v = v.reverse_bits();
    }
    z64_value.into()
}

impl<T1: Transcript<gf2::Domain>, T2: Transcript<z64::Domain>> CombineInstance<T1, T2> {
    fn add_64(
        t: &mut T1,
        a: &[Wire<gf2::Domain>; z64::BIT_SIZE],
        b: &[Wire<gf2::Domain>],
    ) -> [Wire<gf2::Domain>; z64::BIT_SIZE] {
        debug_assert_eq!(b.len(), a.len());

        macro_rules! op_and {
            ($x:expr, $y:expr) => {
                Instance::<gf2::Domain, T1>::op_mul(t, $x, $y)
            };
        }

        macro_rules! op_xor {
            ($x:expr) => ($x);
            ($x:expr, $($y:expr),+) => {
                Instance::<gf2::Domain, T1>::op_add(
                    &$x,
                    &op_xor!($($y),+)
                )
            };
        }

        let mut res: [Wire<gf2::Domain>; z64::BIT_SIZE] =
            unsafe { MaybeUninit::zeroed().assume_init() };

        let mut carry = op_and!(&a[0], &b[0]);

        res[0] = op_xor!(&a[0], &b[0]);

        for i in 1..(z64::BIT_SIZE - 1) {
            // new
            let ac = op_xor!(&a[i], carry);
            let bc = op_xor!(&b[i], carry);
            let ac_bc = op_and!(&ac, &bc);
            res[i] = op_xor!(&ac, &b[i]);
            carry = op_xor!(&ac_bc, &carry);
        }

        res[z64::BIT_SIZE - 1] = op_xor!(&carry, &a[z64::BIT_SIZE - 1], &b[z64::BIT_SIZE - 1]);

        #[cfg(debug_assertions)]
        if T1::IS_PROVER {
            // sanity check: check that reconstructing the bits as 64-bit integers and adding works as expected
            let a_val = recon_gf2_to_z64(gf2::Domain::reconstruct, a);
            let b_val = recon_gf2_to_z64(
                gf2::Domain::reconstruct,
                <&[Wire<gf2::Domain>; z64::BIT_SIZE]>::try_from(b).unwrap(),
            );
            let c_val = recon_gf2_to_z64(gf2::Domain::reconstruct, &res);
            debug_assert_eq!(a_val + b_val, c_val);
        }

        res
    }

    pub fn new(gf2: Instance<gf2::Domain, T1>, z64: Instance<z64::Domain, T2>) -> Self {
        debug_assert_eq!(T1::IS_PROVER, T2::IS_PROVER);
        Self { gf2, z64 }
    }

    pub fn split(self) -> (Instance<gf2::Domain, T1>, Instance<z64::Domain, T2>) {
        (self.gf2, self.z64)
    }

    pub fn hash(&self) -> [Hash; PACKED] {
        let gf2_hash = self.gf2.transcript.hash();
        let z64_hash = self.z64.transcript.hash();

        [
            HASH!(gf2_hash[0].as_bytes(), z64_hash[0].as_bytes()),
            HASH!(gf2_hash[1].as_bytes(), z64_hash[1].as_bytes()),
            HASH!(gf2_hash[2].as_bytes(), z64_hash[2].as_bytes()),
            HASH!(gf2_hash[3].as_bytes(), z64_hash[3].as_bytes()),
            HASH!(gf2_hash[4].as_bytes(), z64_hash[4].as_bytes()),
            HASH!(gf2_hash[5].as_bytes(), z64_hash[5].as_bytes()),
            HASH!(gf2_hash[6].as_bytes(), z64_hash[6].as_bytes()),
            HASH!(gf2_hash[7].as_bytes(), z64_hash[7].as_bytes()),
        ]
    }

    pub fn step(&mut self, operation: &CombineOperation) {
        match operation {
            CombineOperation::SizeHint(z64, gf2) => {
                if self.z64.wires.len() < *z64 {
                    self.z64.wires.resize(*z64, Default::default());
                }
                if self.gf2.wires.len() < *gf2 {
                    self.gf2.wires.resize(*gf2, Default::default());
                }
            }
            CombineOperation::GF2(op) => self.gf2.step(op),
            CombineOperation::GF2AsU8(_) => { unimplemented!("Reverie doesn't support u8-encoded bool operations (and probably never will)") }
            CombineOperation::Z64(op) => self.z64.step(op),
            CombineOperation::Z256(_op) => { unimplemented!("Reverie doesn't support the 256-bit integer ring yet") }
            CombineOperation::B2A(dst, src) => {
                let dst = *dst;
                let src = *src;

                // generate sharing of random 64-bit integer in gf2 and reconstruct in z64
                let (gf2_wires, z64_value) = {
                    // reconstructed 64 value
                    let mut gf2_wires: [Wire<gf2::Domain>; z64::BIT_SIZE] =
                        unsafe { MaybeUninit::zeroed().assume_init() };

                    // generate fresh shares for Boolean circuit
                    for wire in gf2_wires.iter_mut().take(z64::BIT_SIZE) {
                        wire.mask = self.gf2.transcript.new_mask();
                        wire.corr = gf2::Recon::zero();
                    }

                    // reconstruct and convert to z64
                    let z64_value = recon_gf2_to_z64(gf2::Domain::reconstruct, &gf2_wires);
                    (gf2_wires, z64_value)
                };

                // generate share of same value in z64
                let z64_wire = {
                    let z64_mask = self.z64.transcript.new_mask();
                    let z64_mask_recon = z64::Domain::reconstruct(&z64_mask);
                    let z64_corr = z64_value - z64_mask_recon;
                    let z64_corr = self.z64.transcript.correction(z64_corr);
                    // println!("{:?}", z64_corr);
                    Wire::<z64::Domain> {
                        mask: z64_mask,
                        corr: z64_corr,
                    }
                };

                #[cfg(debug_assertions)]
                if T1::IS_PROVER {
                    // only holds during proving
                    debug_assert_eq!(z64_wire.value(), z64_value);
                }

                // run addition circuit in gf2
                // add 64-bit values:
                // a = shares[0:64]
                // b = gf2.wires[from:from+64]
                let gf2_add_res = Self::add_64(
                    &mut self.gf2.transcript,
                    &gf2_wires,
                    &self.gf2.wires[src..src + z64::BIT_SIZE],
                );

                // reconstruct result of addition (record reconstructions: at online time)
                let z64_recon: z64::Recon =
                    recon_gf2_to_z64(|v| self.gf2.transcript.reconstruct(*v), &gf2_add_res);

                #[cfg(debug_assertions)]
                if T1::IS_PROVER {
                    // only holds during proving
                    let src_val = recon_gf2_to_z64(
                        gf2::Domain::reconstruct,
                        <&[Wire<gf2::Domain>; z64::BIT_SIZE]>::try_from(
                            &self.gf2.wires[src..src + z64::BIT_SIZE],
                        )
                        .unwrap(),
                    );
                    debug_assert_eq!(src_val + z64_value, z64_recon);
                    debug_assert_eq!(src_val, z64_recon - z64_wire.value());
                }

                // execute subtraction in z64
                self.z64.wires[dst] = Wire {
                    mask: z64::Share::zero() - z64_wire.mask,
                    corr: z64_recon - z64_wire.corr,
                };

                #[cfg(debug_assertions)]
                if T1::IS_PROVER {
                    // only holds during proving
                    let src_val = recon_gf2_to_z64(
                        gf2::Domain::reconstruct,
                        <&[Wire<gf2::Domain>; z64::BIT_SIZE]>::try_from(
                            &self.gf2.wires[src..src + z64::BIT_SIZE],
                        )
                        .unwrap(),
                    );
                    let dst_val = self.z64.wires[dst].value();
                    debug_assert_eq!(src_val, dst_val);
                }
            }
        }
    }
}
