use super::RingElement;

use std::ops::{Add, Mul, Sub};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scalar(pub(super) u64);

impl Add for Scalar {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self::Output {
        Scalar(self.0 ^ other.0)
    }
}

impl Sub for Scalar {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self::Output {
        Scalar(self.0 ^ other.0)
    }
}

impl Mul for Scalar {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self::Output {
        Scalar(self.0 & other.0)
    }
}

impl RingElement for Scalar {
    const ZERO: Self = Scalar(0);
    const ONE: Self = Scalar(0xffff_ffff_ffff_ffff);
}
