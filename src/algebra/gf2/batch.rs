use super::Bit;
use super::RingBatch;

use std::ops::{Add, Mul, Neg, Sub};

/// Represents an element of the vector space GF(2)^64
#[derive(Copy, Clone)]
pub struct BitBatch(u64);

impl Add for BitBatch {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self(self.0 ^ other.0)
    }
}

impl Sub for BitBatch {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        Self(self.0 ^ other.0)
    }
}

impl Mul for BitBatch {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        Self(self.0 & other.0)
    }
}

impl Neg for BitBatch {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl RingBatch for BitBatch {
    const BATCH_SIZE: usize = 64;

    type Element = Bit;

    fn get(&self, i: usize) -> Bit {
        Bit::new(((self.0 >> i) & 1) as usize)
    }

    fn set(&mut self, i: usize, v: Bit) {
        let m = (v.get() as u64) << i;
        self.0 &= !m;
        self.0 |= m;
        debug_assert_eq!(self.get(i), v);
    }

    fn pack(self) -> u64 {
        self.0
    }

    fn unpack(v: u64) -> Self {
        BitBatch(v)
    }

    fn zero() -> BitBatch {
        Self(0)
    }
}
