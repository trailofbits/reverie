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

mod fieldswitching_proof;
mod proof;

pub use proof::{ProofGf2P64, ProofGf2P64_64, ProofGf2P64_85, ProofGf2P8};

use crate::algebra::RingElement;

use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Instruction<E: RingElement> {
    NrOfWires(usize), // Total nr of wires, should be first (and only first) in circuit
    AddConst(usize, usize, E), // addition of constant
    MulConst(usize, usize, E), // multiplication by constant
    LocalOp(usize, usize), // apply domain-specific local operation
    Mul(usize, usize, usize), // multiplication of two wires
    Add(usize, usize, usize), // addition of two wires
    Branch(usize),    // load next branch element
    Input(usize),     // read next field element from input tape
    Output(usize),    // output wire (write wire-value to output tape)
    Const(usize, E),  // fixed constant value
}

// TODO - 32 --> 64
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum ConnectionInstruction {
    BToA(usize, [usize; 32]), // Change field from GF(2) to GF(2^k) //TODO(gvl): make more flexible, max size of arithmetic ring is now 64 bits
    AToB([usize; 32], usize), // Change field from GF(2^k) to GF(2) //TODO(gvl): make more flexible, max size of arithmetic ring is now 64 bits
    Challenge(usize),         // Input a challenge on a wire
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramTriple<'a,
    I1: Deserialize<'a> + Serialize,
    I2: Deserialize<'a> + Serialize,
    I3: Deserialize<'a> + Serialize,
> {
    pub program_1: Vec<I1>,
    pub program_2: Vec<I2>,
    pub program_3: Vec<I3>,
}

type Instructions<D> = Vec<Instruction<<D as algebra::Domain>::Scalar>>;
