use core::ops::{Add, Mul, Neg, Sub};

use rand_core::RngCore;

pub mod gf2;

pub mod util;

/// Represents a single ring element
pub trait RingElement:
    Sized + Copy + Add<Output = Self> + Sub<Output = Self> + Neg<Output = Self> + Mul<Output = Self>
{
    fn zero() -> Self;
}

/// Represents a batch/vector of ring elements.
/// Ring operations occur component-wise:
/// Hadamard products and addition of vectors.
///
/// The reason for this abstraction is efficiency:
/// e.g. allowing us to represent 64 elements of gf2 in a single 64-bit word.
pub trait RingBatch:
    Sized + Copy + Add<Output = Self> + Sub<Output = Self> + Neg<Output = Self> + Mul<Output = Self>
{
    type Element: RingElement;

    const BATCH_SIZE: usize;

    fn get(&self, i: usize) -> Self::Element;

    fn set(&mut self, i: usize, v: Self::Element);

    fn zero() -> Self;

    fn pack(self) -> u64;

    fn unpack(v: u64) -> Self;

    /// Generate a batch of elements
    ///
    /// Default implementation achieves this by unpacking a packed representation.
    fn gen<G: RngCore>(gen: &mut G) -> Self {
        Self::unpack(gen.next_u64())
    }
}
