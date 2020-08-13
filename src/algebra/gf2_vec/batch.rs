use super::scalar::Scalar;
use super::{Packable, RingElement, Samplable, RingModule, Serializable};

use crate::util::Writer;

use std::convert::TryInto;
use std::io;
use std::ops::{Add, Mul, Sub};

use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch(pub(super) u64);

impl Batch {
    pub fn rotate(&self) -> Batch {
        Batch(self.0.rotate_left(1))
    }
}

impl Serializable for Batch {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.0.to_le_bytes())
    }
}

impl Packable for Batch {
    type Error = ();

    fn pack<'a, W: io::Write, I: Iterator<Item = &'a Batch>>(
        mut dst: W,
        elems: I,
    ) -> io::Result<()> {
        for elem in elems {
            dst.write_all(&elem.0.to_le_bytes())?;
        }
        Ok(())
    }

    fn unpack<W: Writer<Batch>>(mut dst: W, bytes: &[u8]) -> Result<(), ()> {
        if bytes.len() % 8 != 0 {
            return Err(());
        }
        for chunk in bytes.chunks(8) {
            dst.write(Batch(u64::from_le_bytes(chunk.try_into().unwrap())));
        }
        Ok(())
    }
}

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

impl RingModule<Scalar> for Batch {
    const DIMENSION: usize = 1;

    // action of the scalar ring upon the module:
    // s * (r_1, r_2, ..., r_dimension) = (s * r_1, s * r_2, ..., s * r_dimension)
    fn action(&self, s: Scalar) -> Self {
        Batch(self.0 * s.0.0)
    }

    fn set(&mut self, i: usize, s: Scalar) {
        debug_assert_eq!(i, 0);
        *self = s.0;
    }

    fn get(&self, i: usize) -> Scalar {
        Scalar(*self)
    }
}


impl Samplable for Batch {
    fn gen<R: RngCore>(rng: &mut R) -> Batch {
        let mut res: [u8; 8] = [0; 8];
        rng.fill_bytes(&mut res);
        Batch(u64::from_le_bytes(res))
    }
}
