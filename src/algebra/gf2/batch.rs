use super::*;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::io;

pub(super) const BATCH_SIZE_BYTES: usize = 8; // batch is 64-bit / 8 bytes
pub(super) const BATCH_SIZE_BITS: usize = BATCH_SIZE_BYTES * 8;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitBatch(pub(super) [u8; BATCH_SIZE_BYTES]);

impl Packable for BitBatch {
    fn pack<W: Write>(mut dst: W, elems: &[Self]) -> io::Result<()> {
        for elem in elems {
            dst.write_all(&elem.0[..]);
        }
        Ok(())
    }

    fn unpack(bytes: &[u8]) -> Option<Vec<Self>> {
        if bytes.len() % BATCH_SIZE_BYTES != 0 {
            return None;
        }

        let mut res = Vec::with_capacity(bytes.len() / BATCH_SIZE_BYTES);
        for chunk in bytes.chunks(BATCH_SIZE_BYTES) {
            res.push(BitBatch([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]));
        }
        Some(res)
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

    #[inline(always)]
    fn add(self, other: Self) -> Self::Output {
        // LLVM optimizes this into a single XOR between 64-bit integers
        let mut res: [u8; BATCH_SIZE_BYTES] = [0; BATCH_SIZE_BYTES];
        for i in 0..BATCH_SIZE_BYTES {
            res[i] = self.0[i] ^ other.0[i];
        }
        Self(res)
    }
}

impl Sub for BitBatch {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self::Output {
        self + other
    }
}

impl Mul for BitBatch {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self::Output {
        // LLVM optimizes this into a single XOR between 64-bit integers
        let mut res: [u8; BATCH_SIZE_BYTES] = [0; BATCH_SIZE_BYTES];
        for i in 0..BATCH_SIZE_BYTES {
            res[i] = self.0[i] & other.0[i];
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
    fn action(&self, s: BitScalar) -> Self {
        let mut res: [u8; BATCH_SIZE_BYTES] = [0; BATCH_SIZE_BYTES];
        for i in 0..BATCH_SIZE_BYTES {
            res[i] = s.0 * self.0[i];
        }
        Self(res)
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
