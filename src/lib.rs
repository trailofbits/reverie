// This crate relies on const_generics:
// It is simply much less painful to use rather than GenericArray,
// where e.g. it is impossible to enforce equality of lengths for arrays
#![feature(const_generics)]
#![feature(const_int_pow)]
#![allow(incomplete_features)]
#![feature(test)]
#![feature(new_uninit)]
#![feature(stdsimd)]

#[cfg(test)]
extern crate test;

// simple utility functions
#[macro_use]
mod util;

#[cfg(test)]
mod tests;

// abstraction for Fiat-Shamir
pub mod fs;

// pre-processing
pub mod pp;

// puncturable PRF abstractions
pub mod crypto;

// online phase
pub mod online;

// traits and implementations of the underlying ring
pub mod algebra;

// internal constants
mod consts;

use crate::algebra::RingElement;

#[derive(Copy, Clone, Debug)]
pub enum Instruction<E: RingElement> {
    AddConst(usize, usize, E), // addition of constant
    MulConst(usize, usize, E), // multiplication by constant
    Mul(usize, usize, usize),  // multiplication of two wires
    Add(usize, usize, usize),  // addition of two wires
    Output(usize),             // output wire (write wire-value to output)
}

#[cfg(test)]
mod benchmark {
    use crate::algebra::gf2::*;
    use crate::algebra::*;
    use crate::tests::*;

    use crate::online::Proof;
    use crate::pp::PreprocessedProof;

    use rand::thread_rng;
    use test::Bencher;

    #[bench]
    fn bench_gf2p8_proof(b: &mut Bencher) {
        let mut rng = thread_rng();

        let one = <<GF2P8 as Domain>::Sharing as RingModule>::Scalar::ONE;
        let zero = <<GF2P8 as Domain>::Sharing as RingModule>::Scalar::ZERO;
        let inputs: Vec<<<GF2P8 as Domain>::Sharing as RingModule>::Scalar> = vec![one, one, one];

        let program = random_program::<GF2P8, _>(&mut rng, inputs.len(), 1_000_000, false);

        println!("program sampled");

        b.iter(|| {
            PreprocessedProof::<GF2P8, 8, 8, 252, 256, 44>::new(
                [0u8; 16],
                &program[..],
                inputs.len(),
            );
            let keys: [[u8; 16]; 44] = [[0u8; 16]; 44];
            let _: Proof<GF2P8, 8, 8, 44> = Proof::new(&keys, &program, &inputs);
        })
    }
}
