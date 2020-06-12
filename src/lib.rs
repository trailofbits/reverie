#![cfg_attr(feature = "unstable", feature(test))]

#[cfg(test)]
#[cfg(feature = "unstable")]
extern crate test;

// abstraction for Fiat-Shamir
mod fs;

// pre-processing
mod pp;

// puncturable PRF abstractions
mod crypto;

// online phase
mod online;

// traits and implementations of the underlying ring
mod algebra;
