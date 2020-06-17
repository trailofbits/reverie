// This crate relies on const_generics:
// It is simply much less painful to use rather than GenericArray,
// where e.g. it is impossible to enforce equality of lengths for arrays
#![feature(const_generics)]
#![feature(const_int_pow)]
#![allow(incomplete_features)]
#![feature(test)]

#[cfg(test)]
extern crate test;

// simple utility functions
mod util;

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

// internal constants
mod consts;
