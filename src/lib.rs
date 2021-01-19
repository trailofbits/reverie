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

// field switching
pub mod fieldswitching;

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

pub use proof::{ProofGF2P64, ProofGF2P64_64, ProofGF2P64_85, ProofGF2P8};

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

#[derive(Copy, Clone, Debug)]
pub enum ConnectionInstruction {
    Input(usize),              // read next field element from input tape
    Output(usize),             // output wire (write wire-value to output tape)
    BToA(usize, [usize; 2]),      // Change field from GF(2) to GF(2^k) //TODO: make more flexible
    AToB([usize; 2], usize),      // Change field from GF(2^k) to GF(2) //TODO: make more flexible
}

type Instructions<D> = Vec<Instruction<<D as algebra::Domain>::Scalar>>;
