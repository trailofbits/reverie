use super::scalar::Scalar;
use super::{Packable, RingElement, Samplable, RingModule, Serializable};

use crate::util::Writer;

use std::convert::TryInto;
use std::io;
use std::ops::{Add, Mul, Sub};

use rand::Rng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

const LOW_MASK: u64 = (1 << 21) - 1;
const LOW_BYTE_LEN: usize = 3;
const LOW_BIT_LEN: usize = 21;

const HIGH_BYTE_LEN: usize = 8;
const TOTAL_BYTE_LEN: usize = LOW_BYTE_LEN + HIGH_BYTE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch(
    pub(super) u64, // most significant 64 bits of 85-bit scalar
    pub(super) u64  // least significant 21 bits of 85-bit scalar
);

impl Batch {
    pub fn rotate(&self) -> Batch {
        let (w0, _) = self.0.overflowing_shl(1);
        let w1 = (self.1 << 1) & LOW_MASK;
        let b0 = self.0 >> 63;
        let b1 = self.1 >> (LOW_BIT_LEN - 1);
        let w0 = w0 | b1;
        let w1 = w1 | b0;
        debug_assert!(w1 <= LOW_MASK);
        Batch(w0, w1)
    }
}

impl Serializable for Batch {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.1.to_le_bytes()[..LOW_BYTE_LEN])?;
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
            dst.write_all(&elem.1.to_le_bytes()[..LOW_BYTE_LEN])?;
            dst.write_all(&elem.0.to_le_bytes())?;
        }
        Ok(())
    }

    fn unpack<W: Writer<Batch>>(mut dst: W, bytes: &[u8]) -> Result<(), ()> {
        if bytes.len() % TOTAL_BYTE_LEN != 0 {
            return Err(());
        }
        for chunk in bytes.chunks(TOTAL_BYTE_LEN) {
            let w1 = (chunk[0] as u64) | (chunk[1] as u64) << 8 | (chunk[2] as u64) << 16;
            let w0 = u64::from_le_bytes(chunk[LOW_BYTE_LEN..].try_into().unwrap());
            if w1 > LOW_MASK {
                return Err(())
            }
            dst.write(Batch(w0, w1));
        }
        Ok(())
    }
}

impl Add for Batch {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self::Output {
        debug_assert!(self.1 <= LOW_MASK);
        debug_assert!(other.1 <= LOW_MASK);
        Batch(
            self.0 ^ other.0,
            self.1 ^ other.1,
        )
    }
}

impl Sub for Batch {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self::Output {
        debug_assert!(self.1 <= LOW_MASK);
        debug_assert!(other.1 <= LOW_MASK);
        Batch(
            self.0 ^ other.0,
            self.1 ^ other.1
        )
    }
}

impl Mul for Batch {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self::Output {
        debug_assert!(self.1 <= LOW_MASK);
        debug_assert!(other.1 <= LOW_MASK);
        Batch(
            self.0 & other.0,
            self.1 & other.1
        )
    }
}

impl RingElement for Batch {
    const ONE: Self = Batch(0xffff_ffff_ffff_ffff, LOW_MASK);
    const ZERO: Self = Batch(0x0000_0000_0000_0000, 0x0000_0000_0000_0000);
}

impl RingModule<Scalar> for Batch {
    const DIMENSION: usize = 1;

    #[inline(always)]
    fn action(&self, s: Scalar) -> Self {
        Batch(
            self.0 & s.0.0,
            self.1 & s.0.1,
        )
    }

    #[inline(always)]
    fn set(&mut self, i: usize, s: Scalar) {
        debug_assert_eq!(i, 0);
        *self = s.0;
    }

    #[inline(always)]
    fn get(&self, i: usize) -> Scalar {
        debug_assert_eq!(i, 0);
        Scalar(*self)
    }
}

impl Samplable for Batch {
    fn gen<R: RngCore>(rng: &mut R) -> Batch {
        let w0 = u64::from_le_bytes(rng.gen());
        let w1 = u64::from_le_bytes(rng.gen()) & LOW_MASK;
        Batch(w0, w1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_vec85_rotation() {
        let mut rng = thread_rng();
        for _  in 0..100 {
            let org = Batch::gen(&mut rng);

            // rotate 85 times to get id
            let mut rot = org;
            for _ in 0..85 {
                rot = rot.rotate();
            }
            assert_eq!(rot, org);
        }
    }
}