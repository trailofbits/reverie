use super::batch::Batch;
use super::{LocalOperation, Packable, RingElement};

use crate::util::{MapWriter, Writer};

use std::io;
use std::ops::{Add, Mul, Sub};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scalar(pub(super) Batch);

impl Scalar {
    pub const fn new(w0: u64, w1: u64) -> Scalar {
        Scalar(Batch(w0, w1))
    }
}

/// Packing of scalars for this domain is simply the packing of batches.
impl Packable for Scalar {
    type Error = ();

    fn pack<'a, W: io::Write, I: Iterator<Item = &'a Scalar>>(dst: W, elems: I) -> io::Result<()> {
        Batch::pack(dst, elems.map(|v| &v.0))
    }

    fn unpack<W: Writer<Scalar>>(dst: W, bytes: &[u8]) -> Result<(), ()> {
        Batch::unpack(MapWriter::new(Scalar, dst), bytes)
    }
}

/// The local operation for this domain is cyclic left rotation of the vector.
/// This enables the computation of any function between any pair of elements.
impl LocalOperation for Scalar {
    fn operation(&self) -> Scalar {
        Scalar(self.0.rotate())
    }
}

impl Add for Scalar {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self::Output {
        Self(self.0 + other.0)
    }
}

impl Sub for Scalar {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self::Output {
        Self(self.0 - other.0)
    }
}

impl Mul for Scalar {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self::Output {
        Self(self.0 * other.0)
    }
}

impl RingElement for Scalar {
    const ZERO: Self = Scalar(Batch::ZERO);
    const ONE: Self = Scalar(Batch::ONE);
}
