#![feature(test)]

extern crate test;

use serde::{Deserialize, Serialize};

pub use algebra::*;
pub use eval::{evaluate_composite_program, largest_wires};

pub mod algebra;
pub mod crypto;
pub mod eval;
pub mod generator;
pub mod interpreter;
pub mod proof;
pub mod transcript;

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Operation<T> {
    Input(usize),
    Random(usize),
    Sub(usize, usize, usize),
    Add(usize, usize, usize),
    AddConst(usize, usize, T),
    Mul(usize, usize, usize),
    MulConst(usize, usize, T),
    AssertZero(usize),
}

impl<T> Operation<T> {
    pub fn dst(&self) -> Option<usize> {
        match *self {
            Operation::Input(dst) => Some(dst),
            Operation::Random(dst) => Some(dst),
            Operation::Sub(dst, _, _) => Some(dst),
            Operation::Add(dst, _, _) => Some(dst),
            Operation::AddConst(dst, _, _) => Some(dst),
            Operation::Mul(dst, _, _) => Some(dst),
            Operation::MulConst(dst, _, _) => Some(dst),
            Operation::AssertZero(_) => None,
        }
    }
}

/// GF2 and Z64 have separate name-space
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum CombineOperation {
    GF2(Operation<<gf2::Domain as Domain>::ConstType>), // gf2 finite field
    Z64(Operation<<z64::Domain as Domain>::ConstType>), // 64-bit integer ring
    /// Converts a value from the Boolean circuit into a value in the arithmetic circuit.
    ///
    /// Takes: dst, src
    ///
    /// src is a wire index in GF2 namespace containing the least significant bit.
    B2A(usize, usize), // ring switch (gf2 -> 64-bit integer)

    /// Information about the number of wires needed to evaluate the circuit. As with B2A,
    /// first item is Z64, second is GF2.
    SizeHint(usize, usize),
}

pub enum CombOp {
    GF2AND(usize, usize, usize),
    Z64AddConst(usize, usize, u64),
    Z64Mul(usize, usize, usize),
}

// players in MPC protocol
pub const PLAYERS: usize = 8;

// number of instances packed into a single share
pub const PACKED: usize = 8;

/// number of shares per batch
/// e.g. in the case of GF2, each batch is 128-bits,
/// hence a patch per player, per instance (64 in total) is 128 shares
pub const BATCH_SIZE: usize = 128;

/// online repetitions (divisible by 8)
// const ONLINE_REPS: usize = 40;
const ONLINE_REPS: usize = 40;

/// total number of repetitions
// const TOTAL_REPS: usize = 256;
const TOTAL_REPS: usize = 256;

/// preprocessing reps
const PREPROCESSING_REPS: usize = TOTAL_REPS - ONLINE_REPS;

const PACKED_REPS: usize = TOTAL_REPS / PACKED;
