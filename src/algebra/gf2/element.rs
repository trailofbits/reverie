use super::RingElement;

use std::ops::{Add, Mul, Neg, Sub};

#[derive(Copy, Clone)]
pub struct Bit(usize);

impl Bit {
    pub fn new(v: usize) -> Bit {
        debug_assert!(v < 2);
        Bit(v)
    }

    pub fn get(&self) -> usize {
        self.0
    }
}

impl Add for Bit {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self(self.0 ^ other.0)
    }
}

impl Sub for Bit {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        Self(self.0 ^ other.0)
    }
}

impl Mul for Bit {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        Self(self.0 & other.0)
    }
}

impl Neg for Bit {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl RingElement for Bit {
    fn zero() -> Bit {
        Self(0)
    }
}
