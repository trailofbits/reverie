use super::*;

use crate::util::Writer;

use std::convert::TryInto;
use std::fmt;

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scalar(pub u64);

impl LocalOperation for Scalar {}

impl Packable for Scalar {
    type Error = ();

    fn pack<'a, W: io::Write, I: Iterator<Item = &'a Scalar>>(
        mut dst: W,
        elems: I,
    ) -> io::Result<()> {
        for elem in elems {
            dst.write_all(&elem.0.to_le_bytes())?;
        }
        Ok(())
    }

    fn unpack<W: Writer<Scalar>>(mut dst: W, bytes: &[u8]) -> Result<(), ()> {
        if bytes.len() % 8 != 0 {
            return Err(());
        }
        for chunk in bytes.chunks(8) {
            dst.write(Scalar(u64::from_le_bytes(chunk.try_into().unwrap())));
        }
        Ok(())
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self(u64::wrapping_add(self.0, other.0))
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        Self(u64::wrapping_sub(self.0, other.0))
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        Self(u64::wrapping_mul(self.0, other.0))
    }
}

impl RingElement for Scalar {
    const ONE: Self = Self(1);
    const ZERO: Self = Self(0);
}

impl Samplable for Scalar {
    fn gen<R: RngCore>(rng: &mut R) -> Scalar {
        Scalar(rng.gen::<u64>())
    }
}
