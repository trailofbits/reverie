use super::*;

use std::fmt;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct BitScalar(pub(super) u8);

impl fmt::Debug for BitScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl Add for BitScalar {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        debug_assert!(self.0 < 2, "the scalar should be a bit");
        Self(self.0 ^ other.0)
    }
}

impl Sub for BitScalar {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        debug_assert!(self.0 < 2, "scalar is not bit");
        Self(self.0 ^ other.0)
    }
}

impl Mul for BitScalar {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        debug_assert!(self.0 < 2, "scalar is not bit");
        Self(self.0 & other.0)
    }
}

impl RingElement for BitScalar {
    const ONE: Self = Self(1);
    const ZERO: Self = Self(0);
}
