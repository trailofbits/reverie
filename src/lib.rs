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
    Const(usize, E),           // fixed constant value
}

type Instructions<D> = Vec<Instruction<<D as algebra::Domain>::Scalar>>;
