#![feature(const_int_pow)]
#![feature(test)]
#![feature(stdsimd)]

#[cfg(test)]
extern crate test;

// simple utility functions
#[macro_use]
mod util;

#[cfg(test)]
mod tests;

// traits and implementations of the underlying ring
// exposed to enable uses to define programs for the supported rings.
pub mod algebra;

// pre-processing
pub mod preprocessing;

// online phase
pub mod online;

// abstraction for Fiat-Shamir
mod oracle;

// puncturable PRF abstractions
mod crypto;

// internal constants
mod consts;

mod proof;

pub use proof::{ProofGF2P64, ProofGF2P64_64, ProofGF2P8};

use crate::algebra::RingElement;

#[derive(Copy, Clone, Debug)]
pub enum Instruction<E: RingElement> {
    AddConst(usize, usize, E), // addition of constant
    MulConst(usize, usize, E), // multiplication by constant
    LocalOp(usize, usize),     // apply domain-specific local operation
    Mul(usize, usize, usize),  // multiplication of two wires
    Add(usize, usize, usize),  // addition of two wires
    Branch(usize),             // load next branch element
    Input(usize),              // read next field element from input tape
    Output(usize),             // output wire (write wire-value to output tape)
}

/*
#[cfg(test)]
mod testing {
    use crate::algebra::gf2::*;
    use crate::algebra::*;
    use crate::tests::*;

    use crate::online;
    use crate::preprocessing;

    use rand::thread_rng;
    use test::Bencher;

    #[test]
    fn test_gf2p8() {
        let mut rng = thread_rng();

        let one = <<GF2P8 as Domain>::Sharing as RingModule>::Scalar::ONE;
        let zero = <<GF2P8 as Domain>::Sharing as RingModule>::Scalar::ZERO;
        let inputs: Vec<<<GF2P8 as Domain>::Sharing as RingModule>::Scalar> = vec![one, one, one];
        let program = random_program::<GF2P8, _>(&mut rng, inputs.len(), 1000, false);

        // evaluate program in the clear
        let correct_output = evaluate_program::<GF2P8>(&program[..], &inputs[..]);

        // create a proof for the pre-processing phase
        let (pp_proof, output) = preprocessing::Proof::<GF2P8, 8, 8, 252, 256, 44>::new(
            [0u8; 16],
            &program[..],
            inputs.len(),
        );

        // create a proof for the online phase
        let online_proof: online::Proof<GF2P8, 8, 8, 44> =
            online::Proof::new(output, &program, &inputs);

        // verify the pre-processing phase
        let pp_hashes = pp_proof.verify(&program[..], inputs.len()).unwrap();

        // verify the online phase
        let output = online_proof.verify(&program[..]).unwrap();

        // verify that the pre-processing and online phase matches
        assert_eq!(output.check(&pp_hashes), Some(&correct_output[..]));
    }
}
*/
