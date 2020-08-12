use super::*;

use std::ops::{Add, Mul, Sub};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch(pub(super) u64);

impl Add for Batch {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self::Output {
        Batch(self.0 ^ other.0)
    }
}

impl Sub for Batch {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self::Output {
        Batch(self.0 ^ other.0)
    }
}

impl Mul for Batch {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self::Output {
        Batch(self.0 & other.0)
    }
}

impl RingElement for Batch {
    const ONE: Self = Batch(0xffff_ffff_ffff_ffff);
    const ZERO: Self = Batch(0x0000_0000_0000_0000);
}
