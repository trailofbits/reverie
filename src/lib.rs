#![feature(test)]

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

pub use proof::{ProofGf2P64, ProofGf2P64_64, ProofGf2P64_85, ProofGf2P8};

use crate::algebra::RingElement;

use crate::algebra::gf2::BitScalar;
use crate::algebra::z64::Scalar;

#[macro_use]
extern crate serde_big_array;

big_array! { BigArray; }

use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Instruction<E: RingElement> {
    AddConst(usize, usize, E), // addition of constant
    MulConst(usize, usize, E), // multiplication by constant
    LocalOp(usize, usize),     // apply domain-specific local operation
    Mul(usize, usize, usize),  // multiplication of two wires
    Add(usize, usize, usize),  // addition of two wires
    Sub(usize, usize, usize),  // subtraction of one wire from another
    Input(usize),              // read next field element from input tape
    Output(usize),             // output wire (write wire-value to output tape)
    Const(usize, E),           // fixed constant value
    Random(usize),             // Emit a random value
}

type Instructions<D> = Vec<Instruction<<D as algebra::Domain>::Scalar>>;

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum InstructionCombine {
    OpGF2(Instruction<BitScalar>),
    OpZn(Instruction<Scalar>),
    // There's no great way to use [usize; 64] as the set of boolean wire indices for this type
    // (because the other variants are only 32 bytes, and Box isn't copy) so instead we use a tuple
    // of (low index, high index) and grab the bits in between. This means we can't represent
    // non-contiguous segments of bits, but makes inputting zeros easier.
    BToA(usize, (usize, usize)),
}
