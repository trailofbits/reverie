use core::ops::{Add, Mul, Neg, Sub};

use rand_core::RngCore;

mod util;

pub mod gf2;

pub use util::{RingArray, RingVector};

pub trait RingPacked {
    fn as_bytes(&self) -> &[u8];
}

/// Represents a single ring element
pub trait RingElement:
    Sized + Copy + Send + Sync + Add<Output = Self> + Sub<Output = Self> + Neg<Output = Self> + Mul<Output = Self>
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
    Sized + Copy + Send + Sync + Add<Output = Self> + Sub<Output = Self> + Neg<Output = Self> + Mul<Output = Self>
{
    type Element: RingElement;
    type Packed: RingPacked;

    const BATCH_SIZE: usize;

    fn get(&self, i: usize) -> Self::Element;

    fn set(&mut self, i: usize, v: Self::Element);

    fn zero() -> Self;

    /// Packing a batch of ring elements into a serializable type
    fn pack(self) -> Self::Packed;

    /// Unpacking a batch of ring elements
    fn unpack(v: Self::Packed) -> Self;

    /// Generate a batch of elements.
    fn gen<G: RngCore>(gen: &mut G) -> Self;
}

pub trait TransposedBatch<const N: usize, const M: usize>: Sized {
    type Batch: RingBatch;

    fn new(rows: [Self::Batch; N]) -> [Self; M];

    fn get(&self, i: usize) -> <<Self as TransposedBatch<N, M>>::Batch as RingBatch>::Element;
}
