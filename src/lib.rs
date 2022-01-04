#![feature(test)]

extern crate test;

pub use algebra::*;
pub use mcircuit::{evaluate_composite_program, largest_wires};
pub use mcircuit::{CombineOperation, Operation};

pub mod algebra;
pub mod crypto;
pub mod generator;
pub mod interpreter;
pub mod proof;
pub mod transcript;

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
