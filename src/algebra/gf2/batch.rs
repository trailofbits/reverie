use super::Bit;
use super::{RingBatch, RingPacked};

use std::ops::{Add, Mul, Neg, Sub};

use rand::RngCore;

pub struct BitPacked([u8; 8]);

impl RingPacked for BitPacked {
    fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Represents an element of the vector space GF(2)^64
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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
    type Packed = BitPacked;

    fn gen<R: RngCore>(rng: &mut R) -> BitBatch {
        BitBatch(rng.next_u64())
    }

    fn get(&self, i: usize) -> Bit {
        debug_assert!(i < Self::BATCH_SIZE);
        Bit::new(((self.0 >> i) & 1) as usize)
    }

    fn set(&mut self, i: usize, v: Bit) {
        let m = (v.get() as u64) << i;
        self.0 &= !m;
        self.0 |= m;
        debug_assert_eq!(self.get(i), v);
    }

    fn pack(self) -> BitPacked {
        BitPacked(self.0.to_le_bytes())
    }

    fn unpack(v: BitPacked) -> Self {
        BitBatch(u64::from_le_bytes(v.0))
    }

    fn zero() -> BitBatch {
        Self(0)
    }
}
