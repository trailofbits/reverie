use super::*;

use crate::util::Writer;

use std::fmt;

use serde::{Serialize, Deserialize};

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitScalar(pub(super) u8);

impl LocalOperation for BitScalar {}

impl Packable for BitScalar {
    type Error = ();

    fn pack<'a, W: io::Write, I: Iterator<Item = &'a BitScalar>>(
        mut dst: W,
        elems: I,
    ) -> io::Result<()> {
        let mut pac = 0u8;
        let mut rem = 0;

        for bit in elems.cloned() {
            pac <<= 1;
            pac |= bit.0;
            rem += 1;
            if rem == 8 {
                dst.write_all(&[pac])?;
                rem = 0;
            }
        }
        if rem != 0 {
            debug_assert!(rem < 8);
            pac <<= 8 - rem;
            dst.write_all(&[pac])
        } else {
            Ok(())
        }
    }

    fn unpack<W: Writer<BitScalar>>(mut dst: W, bytes: &[u8]) -> Result<(), ()> {
        for v in bytes.iter().cloned() {
            dst.write(BitScalar((v >> 7) & 1));
            dst.write(BitScalar((v >> 6) & 1));
            dst.write(BitScalar((v >> 5) & 1));
            dst.write(BitScalar((v >> 4) & 1));
            dst.write(BitScalar((v >> 3) & 1));
            dst.write(BitScalar((v >> 2) & 1));
            dst.write(BitScalar((v >> 1) & 1));
            dst.write(BitScalar(v & 1));
        }
        Ok(())
    }
}

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

impl Samplable for BitScalar {
    fn gen<R: RngCore>(rng: &mut R) -> BitScalar {
        BitScalar(rng.gen::<u8>() & 1)
    }
}
