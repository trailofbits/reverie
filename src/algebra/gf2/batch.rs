use super::*;

use serde::{Deserialize, Serialize};

use std::convert::TryInto;
use std::fmt;
use std::io;

pub(super) const BATCH_SIZE_BYTES: usize = 8; // batch is 64-bit / 8 bytes
pub(super) const BATCH_SIZE_BITS: usize = BATCH_SIZE_BYTES * 8;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitBatch(pub(super) [u8; BATCH_SIZE_BYTES]);

impl Packable for BitBatch {
    type Error = ();

    fn pack<W: Write>(mut dst: W, elems: &[Self]) -> io::Result<()> {
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

    fn pack(vs: &[BitScalar]) -> BitBatch {
        fn pack(v: &[BitScalar; 8]) -> u8 {
            v[0].0 << 7
                | v[1].0 << 6
                | v[2].0 << 5
                | v[3].0 << 4
                | v[4].0 << 3
                | v[5].0 << 2
                | v[6].0 << 1
                | v[7].0
        }
        BitBatch([
            pack(vs[0x00..0x08].try_into().unwrap()),
            pack(vs[0x08..0x10].try_into().unwrap()),
            pack(vs[0x10..0x18].try_into().unwrap()),
            pack(vs[0x18..0x20].try_into().unwrap()),
            pack(vs[0x20..0x28].try_into().unwrap()),
            pack(vs[0x28..0x30].try_into().unwrap()),
            pack(vs[0x30..0x38].try_into().unwrap()),
            pack(vs[0x38..].try_into().unwrap()),
        ])
    }

    fn unpack(&self, vs: &mut [BitScalar]) {
        fn pack(v: &mut [BitScalar], b: u8) {
            v[7] = BitScalar(b & 1);
            v[6] = BitScalar((b >> 1) & 1);
            v[5] = BitScalar((b >> 2) & 1);
            v[4] = BitScalar((b >> 3) & 1);
            v[3] = BitScalar((b >> 4) & 1);
            v[2] = BitScalar((b >> 5) & 1);
            v[1] = BitScalar((b >> 6) & 1);
            v[0] = BitScalar((b >> 7) & 1);
        }
        pack(&mut vs[0x00..0x08], self.0[0]);
        pack(&mut vs[0x08..0x10], self.0[1]);
        pack(&mut vs[0x10..0x18], self.0[2]);
        pack(&mut vs[0x18..0x20], self.0[3]);
        pack(&mut vs[0x20..0x28], self.0[4]);
        pack(&mut vs[0x28..0x30], self.0[5]);
        pack(&mut vs[0x30..0x38], self.0[6]);
        pack(&mut vs[0x38..0x40], self.0[7]);
    }
}

#[test]
fn test_packing() {
    
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
