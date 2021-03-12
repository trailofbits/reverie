use super::*;

use crate::util::Writer;

use serde::{Deserialize, Serialize};

use std::convert::TryInto;
use std::io;

const PRIME: u64 = 17;

//Batches for Z64 are always dimension 1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch(pub(super) u64);

impl Add for Batch {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn add(self, other: Self) -> Self::Output {
        Self((self.0 + other.0) % PRIME)
    }
}

impl Sub for Batch {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn sub(self, other: Self) -> Self::Output {
        Self((self.0 - other.0) % PRIME)
    }
}

impl Mul for Batch {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn mul(self, other: Self) -> Self::Output {
        Self((self.0 * other.0) % PRIME)
    }
}

impl RingElement for Batch {
    const ONE: Batch = Self(1);
    const ZERO: Batch = Self(0);
}

impl RingModule<Scalar> for Batch {
    const DIMENSION: usize = 1;

    #[inline(always)]
    fn action(&self, s: Scalar) -> Self {
        Self((self.0 * s.0) % PRIME)
    }

    fn get(&self, i: usize) -> Scalar {
        debug_assert_eq!(i, 0);
        Scalar(self.0)
    }

    fn set(&mut self, i: usize, s: Scalar) {
        debug_assert_eq!(i, 0);
        self.0 = s.0;
    }
}

impl Serializable for Batch {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.0.to_le_bytes())
    }
}

//TODO
impl Samplable for Batch {
    fn gen<R: RngCore>(rng: &mut R) -> Batch {
        let res = rng.gen_range::<u64,u64,u64>(0,PRIME);
        Batch(res)
    }
}

impl Packable for Batch {
    type Error = ();

    fn pack<'a, W: io::Write, I: Iterator<Item = &'a Batch>>(
        mut dst: W,
        elems: I,
    ) -> io::Result<()> {
        for batch in elems {
            dst.write_all(&batch.0.to_le_bytes())?;
        }
        Ok(())
    }

    fn unpack<W: Writer<Batch>>(mut dst: W, bytes: &[u8]) -> Result<(), ()> {
        if bytes.len() % 8 != 0 {
            return Err(());
        }

        for chunk in bytes.chunks(8) {
            let batch = u64::from_le_bytes(chunk.try_into().unwrap());
            dst.write(Batch(batch));
        }
        Ok(())
    }
}