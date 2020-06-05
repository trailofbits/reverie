use std::ops::{Add, Mul, Neg, Sub};

// abstraction for Fiat-Shamir
mod fs;

// pre-processing
mod pp;

// PRF and puncturable PRF abstractions
mod prf;

// online phase
mod online;

/// Represents a batch/vector of ring elements.
/// Ring operations occur component-wise:
/// Hadamard products and addition of vectors.
///
/// For efficiency reasons one should pick ring elements with a
/// size dividing the size of the serilization type (u64).
pub trait RingElement: Sized + Add + Sub + Neg + Mul {
    const BIT_SIZE: usize; // size in bits
    const BATCH_SIZE: usize; // number of elements in batch

    /// Packs a batch of ring elements into a 64-bit unsigned integer
    fn pack(self) -> u64;

    /// Unpacks a 64-bit integer as a batch of ring elements
    ///
    /// Warning:
    /// Interface assumes that providing a uniformly random serialized value
    /// results in a vector of uniformly random field elements.
    fn unpack(v: u64) -> Self;
}

/// Represents an element of the vector space GF(2)^64
struct BitField(u64);

impl Add for BitField {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        BitField(self.0 ^ other.0)
    }
}

impl Sub for BitField {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        BitField(self.0 ^ other.0)
    }
}

impl Mul for BitField {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        BitField(self.0 & other.0)
    }
}

/// Note: Negation in the bit-field is a noop:
///
/// - -1 = 1
/// - -0 = 0
impl Neg for BitField {
    type Output = Self;

    fn neg(self) -> Self {
        self
    }
}

impl RingElement for BitField {
    const BIT_SIZE: usize = 1;
    const BATCH_SIZE: usize = 64;

    fn pack(self) -> u64 {
        self.0
    }

    fn unpack(v: u64) -> Self {
        BitField(v)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
