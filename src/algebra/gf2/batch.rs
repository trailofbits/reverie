use super::*;

use crate::util::Writer;

use itertools::izip;
use serde::{Deserialize, Serialize};

use std::fmt;
use std::io;

pub(super) const BATCH_SIZE_BYTES: usize = 8; // batch is 64-bit / 8 bytes
pub(super) const BATCH_SIZE_BITS: usize = BATCH_SIZE_BYTES * 8;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitBatch(pub(super) [u8; BATCH_SIZE_BYTES]);

impl Packable for BitBatch {
    type Error = ();

    fn pack<'a, W: io::Write, I: Iterator<Item = &'a BitBatch>>(
        mut dst: W,
        elems: I,
    ) -> io::Result<()> {
        for elem in elems {
            dst.write_all(&elem.0[..])?;
        }
        Ok(())
    }

    fn unpack<W: Writer<BitBatch>>(mut dst: W, bytes: &[u8]) -> Result<(), ()> {
        if bytes.len() % BATCH_SIZE_BYTES != 0 {
            return Err(());
        }
        for chunk in bytes.chunks(BATCH_SIZE_BYTES) {
            dst.write(BitBatch([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]));
        }
        Ok(())
    }
}

impl fmt::Debug for BitBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "{:08b}-{:08b}-{:08b}-{:08b}-{:08b}-{:08b}-{:08b}-{:08b}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        ))
    }
}

impl Add for BitBatch {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn add(self, other: Self) -> Self::Output {
        // LLVM optimizes this into a single XOR between 64-bit integers
        let mut res: [u8; BATCH_SIZE_BYTES] = [0; BATCH_SIZE_BYTES];
        for (res_byte, self_byte, other_byte) in izip!(&mut res, &self.0, &other.0) {
            *res_byte = self_byte ^ other_byte;
        }
        Self(res)
    }
}

impl Sub for BitBatch {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn sub(self, other: Self) -> Self::Output {
        self + other
    }
}

impl Mul for BitBatch {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn mul(self, other: Self) -> Self::Output {
        // LLVM optimizes this into a single AND between 64-bit integers
        let mut res: [u8; BATCH_SIZE_BYTES] = [0; BATCH_SIZE_BYTES];
        for (res_byte, self_byte, other_byte) in izip!(&mut res, &self.0, &other.0) {
            *res_byte = self_byte & other_byte;
        }
        Self(res)
    }
}

impl RingElement for BitBatch {
    const ONE: BitBatch = BitBatch([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    const ZERO: BitBatch = BitBatch([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

impl RingModule<BitScalar> for BitBatch {
    const DIMENSION: usize = BATCH_SIZE_BITS;

    #[inline(always)]
    fn action(&self, scalar: BitScalar) -> Self {
        let mut res: [u8; BATCH_SIZE_BYTES] = [0; BATCH_SIZE_BYTES];
        for (res_byte, self_byte) in res.iter_mut().zip(&self.0) {
            *res_byte = scalar.0 * self_byte;
        }
        Self(res)
    }

    fn get(&self, i: usize) -> BitScalar {
        let off = 7 - i % 8;
        let idx = i / 8;
        BitScalar((self.0[idx] >> off) & 1)
    }

    fn set(&mut self, i: usize, s: BitScalar) {
        let off = 7 - i % 8;
        let idx = i / 8;
        self.0[idx] &= !(1 << off);
        self.0[idx] |= s.0 << off;
    }
}

impl Serializable for BitBatch {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.0)
    }
}

impl Samplable for BitBatch {
    fn gen<R: RngCore>(rng: &mut R) -> BitBatch {
        let mut res: [u8; 8] = [0; 8];
        rng.fill_bytes(&mut res);
        BitBatch(res)
    }
}
