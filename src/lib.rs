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

// abstraction for Fiat-Shamir
pub mod fs;

// pre-processing
pub mod pp;

// puncturable PRF abstractions
pub mod crypto;

// online phase
// pub mod online;

// traits and implementations of the underlying ring
pub mod algebra;

// internal constants
mod consts;
